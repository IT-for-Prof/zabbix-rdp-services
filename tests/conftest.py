"""Shared test fixtures: a fake RDP server that speaks X.224 then TLS."""
from __future__ import annotations

import contextlib
import datetime as dt
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Make the external script importable as `rdp_check`.
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts" / "externalscripts"))


def _self_signed(cn: str, days: int) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
    )


def _read_tpkt(conn: socket.socket) -> bytes:
    head = b""
    while len(head) < 4:
        c = conn.recv(4 - len(head))
        if not c:
            raise OSError("closed")
        head += c
    total = struct.unpack("!H", head[2:4])[0]
    body = b""
    while len(body) < total - 4:
        c = conn.recv(total - 4 - len(body))
        if not c:
            raise OSError("closed")
        body += c
    return head + body


class FakeRDP(threading.Thread):
    """Accepts connections, replies with an RDP_NEG_RSP, then does TLS (unless RDP)."""

    def __init__(self, selected: int, cn: str = "fake.rdp.local", expiry_days: int = 90,
                 nla_enforced: bool = False, delay: float = 0.0, omit_neg: bool = False):
        super().__init__(daemon=True)
        self.selected = selected
        self.nla_enforced = nla_enforced
        self.delay = delay
        self.omit_neg = omit_neg
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port: int = self._sock.getsockname()[1]
        self._stopped = False
        pem, key = _self_signed(cn, expiry_days)
        self._tmp = tempfile.TemporaryDirectory()
        self._cpath = Path(self._tmp.name) / "c.pem"
        self._kpath = Path(self._tmp.name) / "k.pem"
        self._cpath.write_bytes(pem)
        self._kpath.write_bytes(key)

    def run(self) -> None:
        while not self._stopped:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            with contextlib.suppress(OSError, ssl.SSLError):
                self._serve(conn)

    def _serve(self, conn: socket.socket) -> None:
        if self.delay:
            time.sleep(self.delay)
        cr = _read_tpkt(conn)
        requested = struct.unpack("<I", cr[-4:])[0] if len(cr) >= 4 else 0
        if self.omit_neg:  # legacy Standard Security: confirm X.224 with no RDP_NEG field
            body = b"\xd0\x00\x00\x00\x00\x00"
            x224 = struct.pack("!B", len(body)) + body
            conn.sendall(struct.pack("!BBH", 0x03, 0x00, 4 + len(x224)) + x224)
            conn.close()
            return
        if self.nla_enforced and requested == 0x00000001:  # SSL-only probe rejected
            neg = struct.pack("<BBHI", 0x03, 0x00, 0x0008, 0x05)  # FAILURE / HYBRID_REQUIRED
            body = b"\xd0\x00\x00\x00\x00\x00" + neg
            x224 = struct.pack("!B", len(body)) + body
            conn.sendall(struct.pack("!BBH", 0x03, 0x00, 4 + len(x224)) + x224)
            conn.close()
            return
        neg = struct.pack("<BBHI", 0x02, 0x00, 0x0008, self.selected)
        body = b"\xd0\x00\x00\x00\x00\x00" + neg
        x224 = struct.pack("!B", len(body)) + body
        conn.sendall(struct.pack("!BBH", 0x03, 0x00, 4 + len(x224)) + x224)
        if self.selected == 0x00000000:  # PROTOCOL_RDP -> no TLS layer
            conn.close()
            return
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self._cpath, self._kpath)
        with contextlib.suppress(OSError, ssl.SSLError), ctx.wrap_socket(
            conn, server_side=True
        ) as tls:
            with contextlib.suppress(OSError):
                tls.recv(1)

    def stop(self) -> None:
        self._stopped = True
        with contextlib.suppress(OSError):
            self._sock.close()
        self._tmp.cleanup()


@pytest.fixture
def fake_rdp() -> Iterator[Callable[..., FakeRDP]]:
    servers: list[FakeRDP] = []

    def _make(selected: int, cn: str = "fake.rdp.local", expiry_days: int = 90,
              nla_enforced: bool = False, delay: float = 0.0, omit_neg: bool = False) -> FakeRDP:
        srv = FakeRDP(selected, cn, expiry_days, nla_enforced, delay, omit_neg)
        srv.start()
        servers.append(srv)
        return srv

    yield _make
    for srv in servers:
        srv.stop()
