from pathlib import Path

from cryptography import x509

import rdp_check as rdp

FX = Path(__file__).parent / "fixtures"


def test_grab_cert_self_signed(fake_rdp):
    srv = fake_rdp(rdp.PROTOCOL_SSL, cn="fake.rdp.local", expiry_days=90)
    out = rdp.grab_cert("127.0.0.1", srv.port, "fake.rdp.local", timeout=5.0)
    assert out["security_layer"] == "ssl"
    assert out["cert"]["self_signed"] is True
    assert out["cert"]["subject_cn"] == "fake.rdp.local"
    assert out["cert"]["hostname_match"] is True
    assert 88 <= out["cert"]["days_to_expiry"] <= 90
    assert out["tls"]["version"].startswith("TLS")
    # v0.2 enrichment
    assert out["cert"]["key_type"] == "RSA"
    assert out["cert"]["key_bits"] == 2048
    assert out["cert"]["sig_algorithm"] == "sha256"
    assert out["cert"]["valid_now"] is True


def test_grab_cert_hostname_mismatch(fake_rdp):
    srv = fake_rdp(rdp.PROTOCOL_SSL, cn="other.local")
    out = rdp.grab_cert("127.0.0.1", srv.port, "expected.local", timeout=5.0)
    assert out["cert"]["hostname_match"] is False


def test_grab_cert_hybrid_layer(fake_rdp):
    srv = fake_rdp(rdp.PROTOCOL_HYBRID, cn="fake.rdp.local")
    out = rdp.grab_cert("127.0.0.1", srv.port, "fake.rdp.local", timeout=5.0)
    assert out["security_layer"] == "hybrid"


def test_legacy_rdp_no_tls(fake_rdp):
    srv = fake_rdp(rdp.PROTOCOL_RDP)
    out = rdp.grab_cert("127.0.0.1", srv.port, "x", timeout=5.0)
    assert out["security_layer"] == "rdp"
    assert out["cert"] is None


def test_run_cert_payload(fake_rdp):
    srv = fake_rdp(rdp.PROTOCOL_SSL, cn="fake.rdp.local")
    out = rdp.run_cert("127.0.0.1", srv.port, "fake.rdp.local", timeout=5.0)
    assert out["ok"] is True
    assert out["schema_version"] == rdp.SCHEMA_VERSION
    assert out["cert"]["chain_valid"] is False  # self-signed never chains to system trust
    assert out["host"] == "127.0.0.1"
    assert out["port"] == srv.port


# --- real captured certs (Phase 0 fixtures) -------------------------------- #
def test_describe_real_self_signed():
    cert = x509.load_der_x509_certificate((FX / "selfsigned_cert.der").read_bytes())
    d = rdp.describe_cert(cert, "ts02.example-a.com")
    assert d["self_signed"] is True
    assert d["subject_cn"]
    assert isinstance(d["days_to_expiry"], int)


def test_describe_real_ca_cert():
    cert = x509.load_der_x509_certificate((FX / "ca_signed_cert.der").read_bytes())
    d = rdp.describe_cert(cert, "ts1.example.com")
    assert d["self_signed"] is False
    assert d["issuer"]                       # e.g. "R13"
    assert d["hostname_match"] is True       # cert CN/SAN is ts1.example.com
