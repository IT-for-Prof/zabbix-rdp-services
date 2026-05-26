import struct
from pathlib import Path

import pytest

import rdp_check as rdp

FX = Path(__file__).parent / "fixtures"


def _cc(neg_type: int, value: int) -> bytes:
    neg = struct.pack("<BBHI", neg_type, 0x00, 0x0008, value)
    body = b"\xd0\x00\x00\x12\x34\x00" + neg  # CC+CDT, DST, SRC, class
    x224 = struct.pack("!B", len(body)) + body
    return struct.pack("!BBH", 0x03, 0x00, 4 + len(x224)) + x224


def test_parse_failure_hybrid_required():
    cc = rdp.parse_x224_cc(_cc(rdp.NEG_TYPE_FAILURE, rdp.FAIL_HYBRID_REQUIRED))
    assert cc == {"neg_type": rdp.NEG_TYPE_FAILURE, "value": rdp.FAIL_HYBRID_REQUIRED}


def test_parse_rsp_ssl_selected():
    cc = rdp.parse_x224_cc(_cc(rdp.NEG_TYPE_RSP, rdp.PROTOCOL_SSL))
    assert cc["neg_type"] == rdp.NEG_TYPE_RSP
    assert cc["value"] == rdp.PROTOCOL_SSL


def test_parse_non_rdp_raises():
    with pytest.raises(ValueError):
        rdp.parse_x224_cc(b"HTTP/1.1 400 Bad Request\r\n")


# --- real captured PDUs (Phase 0 fixtures) --------------------------------- #
def test_real_nla_enforced_fixture():
    cc = rdp.parse_x224_cc((FX / "nla_enforced_failure.bin").read_bytes())
    assert cc["neg_type"] == rdp.NEG_TYPE_FAILURE
    assert cc["value"] == rdp.FAIL_HYBRID_REQUIRED  # 0x5


def test_real_nla_optional_fixture():
    cc = rdp.parse_x224_cc((FX / "nla_optional_rsp.bin").read_bytes())
    assert cc["neg_type"] == rdp.NEG_TYPE_RSP
    assert cc["value"] == rdp.PROTOCOL_SSL


def test_real_legacy_failure_fixture():
    cc = rdp.parse_x224_cc((FX / "nla_legacy_failure.bin").read_bytes())
    assert cc["neg_type"] == rdp.NEG_TYPE_FAILURE
    assert cc["value"] == 0x2  # SSL_NOT_ALLOWED_BY_SERVER


# --- live socket path via the fake RDP server ------------------------------ #
def test_check_nla_enforced_socket(fake_rdp):
    # server rejects the SSL-only probe with HYBRID_REQUIRED (0x5) -> NLA enforced
    srv = fake_rdp(rdp.PROTOCOL_HYBRID, nla_enforced=True)
    assert rdp.check_nla("127.0.0.1", srv.port, timeout=5.0) is True


def test_check_nla_not_enforced_socket(fake_rdp):
    srv = fake_rdp(rdp.PROTOCOL_SSL)  # server accepts SSL-only -> NLA not enforced
    assert rdp.check_nla("127.0.0.1", srv.port, timeout=5.0) is False


def test_run_cert_nla_enforced_grabs_cert(fake_rdp):
    # NLA enforced, but the cert is still readable via the HYBRID negotiation path
    srv = fake_rdp(rdp.PROTOCOL_HYBRID, cn="fake.rdp.local", nla_enforced=True)
    out = rdp.run_cert("127.0.0.1", srv.port, "fake.rdp.local", timeout=5.0)
    assert out["nla_enforced"] is True
    assert out["security_layer"] == "hybrid"
    assert out["cert"]["subject_cn"] == "fake.rdp.local"


def test_check_nla_indeterminate_socket(fake_rdp):
    # legacy Standard Security: server confirms X.224 with no RDP_NEG field
    srv = fake_rdp(rdp.PROTOCOL_RDP, omit_neg=True)
    assert rdp.check_nla("127.0.0.1", srv.port, timeout=5.0) is None


def test_run_cert_omits_nla_when_indeterminate(fake_rdp):
    # NLA undeterminable (no RDP_NEG, like nvr) -> key omitted entirely so the
    # Zabbix dependent gets a clean JSONPath no-match instead of an unparseable null
    srv = fake_rdp(rdp.PROTOCOL_RDP, omit_neg=True)
    out = rdp.run_cert("127.0.0.1", srv.port, "x", timeout=5.0)
    assert "nla_enforced" not in out
    assert out["security_layer"] == "rdp"
    assert out["cert"] is None
