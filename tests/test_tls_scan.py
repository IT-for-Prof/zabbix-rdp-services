import time

import rdp_check as rdp


def test_tls_scan_budget_breaks_early_on_slow_host(fake_rdp):
    # server stalls ~2s per connection; the total-budget loop must break early,
    # not pay 4 x 2s. With timeout=3 it gets ~1 probe then breaks.
    srv = fake_rdp(rdp.PROTOCOL_HYBRID, delay=2.0)
    t0 = time.monotonic()
    out = rdp.run_tls_scan("127.0.0.1", srv.port, timeout=3.0)
    elapsed = time.monotonic() - t0
    assert out["ok"] is True
    assert elapsed < 5.5  # would be ~8s (4x2s) without the deadline break


def test_tls_scan_reports_supported_and_weak(fake_rdp):
    srv = fake_rdp(rdp.PROTOCOL_HYBRID)
    out = rdp.run_tls_scan("127.0.0.1", srv.port, timeout=5.0)
    assert out["ok"] is True
    assert isinstance(out["supported_protocols"], list)
    assert isinstance(out["weak_findings"], list)
    assert out["weak_count"] == len(out["weak_findings"])
    # Python's default TLS server offers 1.2/1.3 (not 1.0/1.1).
    assert "TLSv1.2" in out["supported_protocols"] or "TLSv1.3" in out["supported_protocols"]
