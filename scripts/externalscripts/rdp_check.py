#!/usr/bin/env python3
# rdp_check.py — best-practice RDP monitoring for Zabbix 7.0
# Copyright (c) 2025-2026 Konstantin Tyutyunnik / IT for Prof — https://itforprof.com
# Project & docs: https://github.com/IT-for-Prof/zabbix-rdp-services
# SPDX-License-Identifier: MIT
"""RDP service check for Zabbix: cert / tls-scan / discover-tls / self-test.

Performs the RDP/X.224 negotiation (MS-RDPBCGR) needed to reach the TLS layer,
then reports the certificate (expiry, trust, key strength, signature algorithm),
NLA enforcement, security layer, and TLS posture as JSON for Zabbix dependent
items + LLD. No third-party RDP library; stdlib ssl + cryptography only.
Envelope matches the sibling web_check.py contract.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import socket
import ssl
import struct
import time
import warnings
from datetime import UTC, datetime
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

__version__ = "0.2.0"
__author__ = "Konstantin Tyutyunnik / IT for Prof"
__license__ = "MIT"
__url__ = "https://github.com/IT-for-Prof/zabbix-rdp-services"
SCHEMA_VERSION = 1

# MS-RDPBCGR negotiation constants
PROTOCOL_RDP = 0x00000000
PROTOCOL_SSL = 0x00000001
PROTOCOL_HYBRID = 0x00000002
PROTOCOL_HYBRID_EX = 0x00000008
NEG_TYPE_RSP = 0x02
NEG_TYPE_FAILURE = 0x03
FAIL_HYBRID_REQUIRED = 0x05  # HYBRID_REQUIRED_BY_SERVER

# PDU layout constants (avoid magic numbers)
TPKT_VERSION = 0x03
X224_CR = 0xE0
NEG_REQ_LEN = 0x0008
MIN_CC_LEN = 5
NEG_FIELD_LEN = 8

WEAK_TLS = ("TLSv1.0", "TLSv1.1")


# --------------------------------------------------------------------------- #
# Output envelope (matches web_check.py)
# --------------------------------------------------------------------------- #
def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def emit(payload: dict[str, Any] | list[dict[str, Any]]) -> None:
    print(json.dumps(payload, separators=(",", ":"), default=str))
    raise SystemExit(0)


def error_envelope(error_code: str, message: str, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"ok": False, "schema_version": SCHEMA_VERSION,
                           "checked_at": now_iso(), "error_code": error_code,
                           "error_message": message[:300]}
    out.update(extra)
    return out


# --------------------------------------------------------------------------- #
# TLS context helpers
# --------------------------------------------------------------------------- #
def _unverified_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _seclevel0(ctx: ssl.SSLContext) -> None:
    """Lower OpenSSL security level so legacy protocols/ciphers can negotiate."""
    with contextlib.suppress(ssl.SSLError):
        ctx.set_ciphers("ALL:@SECLEVEL=0")


def _cert_attr_utc(cert: Any, name_a: str, name_utc: str) -> datetime:
    """cryptography 41 -> not_valid_after, 42+ -> not_valid_after_utc. Shim."""
    if hasattr(cert, name_utc):
        val_utc: datetime = getattr(cert, name_utc)
        return val_utc
    val: datetime = getattr(cert, name_a)
    return val.replace(tzinfo=UTC) if val.tzinfo is None else val


def _hostname_covered(host: str, names: list[str]) -> bool:
    """Wildcard-aware host vs SAN/CN matching (single wildcard label)."""
    host = host.lower()
    for raw in names:
        if not raw:
            continue
        n = raw.lower()
        if n == host:
            return True
        if n.startswith("*."):
            tail = n[2:]
            if host.endswith("." + tail) and host.count(".") == tail.count(".") + 1:
                return True
    return False


# --------------------------------------------------------------------------- #
# X.224 / RDP negotiation
# --------------------------------------------------------------------------- #
def build_x224_cr(requested_protocols: int) -> bytes:
    """Build a TPKT + X.224 Connection Request carrying an RDP_NEG_REQ."""
    neg_req = struct.pack("<BBHI", 0x01, 0x00, NEG_REQ_LEN, requested_protocols)
    body = bytes([X224_CR]) + b"\x00\x00\x00\x00\x00" + neg_req  # CR+CDT, DST, SRC, class
    x224 = struct.pack("!B", len(body)) + body                   # LI + body
    return struct.pack("!BBH", TPKT_VERSION, 0x00, 4 + len(x224)) + x224


def _recvn(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed during read")
        buf += chunk
    return buf


def recv_tpkt(sock: socket.socket) -> bytes:
    head = _recvn(sock, 4)
    if head[0] != TPKT_VERSION:
        raise ValueError("not a TPKT response (likely not RDP)")
    total = struct.unpack("!H", head[2:4])[0]
    return head + _recvn(sock, total - 4)


def parse_x224_cc(data: bytes) -> dict[str, int | None]:
    """Parse a Connection Confirm; return {neg_type, value} or Nones if absent."""
    if len(data) < MIN_CC_LEN or data[0] != TPKT_VERSION:
        raise ValueError("not a TPKT/X.224 response (likely not RDP)")
    li = data[4]
    rest = data[5 + 6 : 4 + 1 + li]  # skip CC(1)+DST(2)+SRC(2)+class(1) after LI
    if len(rest) < NEG_FIELD_LEN:
        return {"neg_type": None, "value": None}
    return {"neg_type": rest[0], "value": struct.unpack("<I", rest[4:8])[0]}


def negotiate(sock: socket.socket, requested_protocols: int) -> dict[str, int | None]:
    sock.sendall(build_x224_cr(requested_protocols))
    return parse_x224_cc(recv_tpkt(sock))


def check_nla(host: str, port: int, timeout: float = 10.0) -> bool | None:
    """True == NLA enforced (server rejects SSL-only with HYBRID_REQUIRED)."""
    with socket.create_connection((host, port), timeout) as s:
        s.settimeout(timeout)
        cc = negotiate(s, PROTOCOL_SSL)
    if cc["neg_type"] == NEG_TYPE_FAILURE and cc["value"] == FAIL_HYBRID_REQUIRED:
        return True
    if cc["neg_type"] == NEG_TYPE_RSP:
        return False
    return None


# --------------------------------------------------------------------------- #
# Certificate description
# --------------------------------------------------------------------------- #
def _first_cn(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def _san_dns(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    san = cast(x509.SubjectAlternativeName, ext.value)
    return list(san.get_values_for_type(x509.DNSName))


def _key_info(cert: x509.Certificate) -> tuple[str, int]:
    """Return (key_type, key_bits): RSA/EC/<name>, bit length."""
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "EC", pub.curve.key_size
    return type(pub).__name__, int(getattr(pub, "key_size", 0))


def describe_cert(cert: x509.Certificate, hostname: str) -> dict[str, Any]:
    not_after = _cert_attr_utc(cert, "not_valid_after", "not_valid_after_utc")
    not_before = _cert_attr_utc(cert, "not_valid_before", "not_valid_before_utc")
    now = datetime.now(UTC)
    cn = _first_cn(cert.subject)
    names = _san_dns(cert) + ([cn] if cn else [])
    key_type, key_bits = _key_info(cert)
    sig = cert.signature_hash_algorithm
    return {
        "subject_cn": cn,
        "issuer": _first_cn(cert.issuer),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_to_expiry": (not_after - now).days,
        "self_signed": cert.subject == cert.issuer,
        "hostname_match": _hostname_covered(hostname, names),
        "chain_valid": False,
        "valid_now": not_before <= now <= not_after,
        "key_type": key_type,
        "key_bits": key_bits,
        "sig_algorithm": sig.name if sig else "unknown",
    }


# --------------------------------------------------------------------------- #
# Cert grab + chain validation
# --------------------------------------------------------------------------- #
def grab_cert(host: str, port: int, hostname: str, timeout: float = 10.0) -> dict[str, Any]:
    with socket.create_connection((host, port), timeout) as s:
        s.settimeout(timeout)
        cc = negotiate(s, PROTOCOL_HYBRID | PROTOCOL_SSL)
        selected = cc["value"]
        if cc["neg_type"] != NEG_TYPE_RSP or selected is None or selected == PROTOCOL_RDP:
            return {"security_layer": "rdp", "tls": None, "cert": None}
        with _unverified_ctx().wrap_socket(s, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            version = tls.version()
            cipher = tls.cipher()
    if der is None:
        raise ValueError("no peer certificate after TLS handshake")
    cert = x509.load_der_x509_certificate(der)
    layer = "hybrid" if selected & (PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX) else "ssl"
    return {"security_layer": layer,
            "tls": {"version": version, "cipher": cipher[0] if cipher else None},
            "cert": describe_cert(cert, hostname)}


def _chain_validates(host: str, port: int, timeout: float) -> bool:
    """Chain-only validation against the node trust store (hostname NOT checked,
    so it is independent of hostname_match)."""
    try:
        with socket.create_connection((host, port), timeout) as s:
            s.settimeout(timeout)
            cc = negotiate(s, PROTOCOL_HYBRID | PROTOCOL_SSL)
            if cc["neg_type"] != NEG_TYPE_RSP or cc["value"] in (None, PROTOCOL_RDP):
                return False
            ctx = ssl.create_default_context()
            ctx.check_hostname = False  # chain-only; hostname handled separately
            with ctx.wrap_socket(s, server_hostname=host):
                return True
    except (ssl.SSLError, ssl.CertificateError, OSError):
        return False


def run_cert(host: str, port: int, hostname: str, timeout: float = 10.0) -> dict[str, Any]:
    # `timeout` is the TOTAL time budget; each connection gets the remaining slice
    # so worst-case wall time stays ~timeout regardless of connection count.
    deadline = time.monotonic() + timeout

    def _left() -> float:
        return deadline - time.monotonic()  # raw remaining; call sites clamp to >=1.0

    out: dict[str, Any] = {"ok": True, "schema_version": SCHEMA_VERSION,
                           "checked_at": now_iso(), "host": host, "port": port}
    out["nla_enforced"] = check_nla(host, port, max(1.0, _left()))
    info = grab_cert(host, port, hostname, max(1.0, _left()))
    out.update(info)
    # Chain validation is an optional 3rd connection: skip it for self-signed certs
    # (never chain anyway) and when the time budget is spent, so a slow host can't
    # compound a third phase past the deadline.
    if info["cert"] is not None and not info["cert"]["self_signed"] and _left() > 1.0:
        out["cert"]["chain_valid"] = _chain_validates(host, port, max(1.0, _left()))
    return out


# --------------------------------------------------------------------------- #
# TLS posture (Tier C) + LLD
# --------------------------------------------------------------------------- #
def _try_tls_version(host: str, port: int, ver: ssl.TLSVersion, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout) as s:
            s.settimeout(timeout)
            cc = negotiate(s, PROTOCOL_HYBRID | PROTOCOL_SSL)
            if cc["neg_type"] != NEG_TYPE_RSP or cc["value"] in (None, PROTOCOL_RDP):
                return False
            ctx = _unverified_ctx()
            with warnings.catch_warnings():  # TLSv1/1.1 enum is deprecated; probing is intentional
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ver
                ctx.maximum_version = ver
            _seclevel0(ctx)
            with ctx.wrap_socket(s, server_hostname=host):
                return True
    except (ssl.SSLError, OSError, ValueError):
        return False


def scan_protocols(host: str, port: int, timeout: float) -> list[str]:
    # `timeout` is the TOTAL budget across all version probes (bounds wall time
    # so an unreachable host can't cost 4x the per-connection timeout).
    deadline = time.monotonic() + timeout
    matrix = [
        ("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]
    supported: list[str] = []
    for name, ver in matrix:
        remaining = deadline - time.monotonic()
        if remaining <= 1.0:
            break
        if _try_tls_version(host, port, ver, min(timeout, remaining)):
            supported.append(name)
    return supported


def run_tls_scan(host: str, port: int, timeout: float = 10.0) -> dict[str, Any]:
    supported = scan_protocols(host, port, timeout)
    weak = [{"category": "protocol", "name": n, "severity": "WARNING"}
            for n in supported if n in WEAK_TLS]
    return {"ok": True, "schema_version": SCHEMA_VERSION, "checked_at": now_iso(),
            "host": host, "port": port, "supported_protocols": supported,
            "weak_findings": weak, "weak_count": len(weak)}


def run_discover_tls(host: str, port: int, timeout: float = 10.0) -> list[dict[str, str]]:
    """LLD: one entry per weak protocol offered (drives item/trigger prototypes)."""
    return [{"{#RDP_TLS_PROTO}": n, "{#RDP_TLS_CATEGORY}": "protocol"}
            for n in scan_protocols(host, port, timeout) if n in WEAK_TLS]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _is_ipv6(s: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, s)
    except OSError:
        return False
    return True


def _split_target(target: str, default_port: int = 3389) -> tuple[str, int]:
    if target.startswith("["):                       # [ipv6]:port
        host, _, rest = target[1:].partition("]")
        tail = rest.lstrip(":")
        return host, int(tail) if tail else default_port
    if target.count(":") > 1:                         # IPv6: bare, or ipv6:port
        head, _, tail = target.rpartition(":")
        if tail.isdigit() and _is_ipv6(head):         # valid IPv6 head + numeric tail -> port
            return head, int(tail)
        return target, default_port                  # bare IPv6 (no port)
    head, sep, tail = target.rpartition(":")          # host:port / ipv4:port
    if sep and tail.isdigit():
        return head, int(tail)
    return target, default_port                      # bare host


def cmd_cert(args: argparse.Namespace) -> None:
    host, port = _split_target(args.target)
    hostname = args.hostname or host
    try:
        emit(run_cert(host, port, hostname, args.timeout))
    except (ConnectionError, OSError) as exc:
        emit(error_envelope("unreachable", str(exc), host=host, port=port))
    except ValueError as exc:
        emit(error_envelope("not_rdp", str(exc), host=host, port=port))


def cmd_tls_scan(args: argparse.Namespace) -> None:
    host, port = _split_target(args.target)
    try:
        emit(run_tls_scan(host, port, args.timeout))
    except (ConnectionError, OSError, ValueError) as exc:
        emit(error_envelope("unreachable", str(exc), host=host, port=port))


def cmd_discover_tls(args: argparse.Namespace) -> None:
    host, port = _split_target(args.target)
    try:
        emit(run_discover_tls(host, port, args.timeout))
    except (ConnectionError, OSError, ValueError):
        emit([])  # LLD: emit empty array on failure (no discovered prototypes)


def cmd_self_test(_: argparse.Namespace) -> None:
    pkt = build_x224_cr(PROTOCOL_SSL)
    ok = pkt[:2] == b"\x03\x00" and pkt[5] == X224_CR
    emit({"ok": bool(ok), "schema_version": SCHEMA_VERSION, "checked_at": now_iso()})


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rdp_check.py", description="RDP service check for Zabbix")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    pc = sub.add_parser("cert", help="X.224 negotiation + TLS cert/NLA JSON")
    pc.add_argument("target", help="host or host:port")
    pc.add_argument("--hostname", default=None, help="name to match cert SAN/CN against")
    pc.add_argument("--timeout", type=float, default=10.0)
    pc.set_defaults(func=cmd_cert)
    pt = sub.add_parser("tls-scan", help="daily TLS protocol posture")
    pt.add_argument("target", help="host or host:port")
    pt.add_argument("--timeout", type=float, default=10.0)
    pt.set_defaults(func=cmd_tls_scan)
    pd = sub.add_parser("discover-tls", help="LLD: weak TLS protocols")
    pd.add_argument("target", help="host or host:port")
    pd.add_argument("--timeout", type=float, default=10.0)
    pd.set_defaults(func=cmd_discover_tls)
    ps = sub.add_parser("self-test", help="offline smoke check")
    ps.set_defaults(func=cmd_self_test)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
