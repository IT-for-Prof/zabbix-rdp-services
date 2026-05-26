import rdp_check as rdp


def test_split_target_host_port():
    assert rdp._split_target("ts02.example.com:49391") == ("ts02.example.com", 49391)


def test_split_target_bare_host_default_port():
    assert rdp._split_target("host.example.com") == ("host.example.com", 3389)


def test_split_target_ipv6_bracketed():
    assert rdp._split_target("[2001:db8::1]:3389") == ("2001:db8::1", 3389)


def test_split_target_ipv6_with_port():
    # {HOST.CONN}:{$RDP_PORT} for a bare IPv6 -> last :digits is the port
    assert rdp._split_target("2001:db8::1:33899") == ("2001:db8::1", 33899)


def test_split_target_ipv6_bare_no_port():
    # a bare IPv6 (no port) must stay intact, not be mis-split on its last hextet
    assert rdp._split_target("2001:db8::1") == ("2001:db8::1", 3389)
    assert rdp._split_target("fe80::1") == ("fe80::1", 3389)


def test_discover_tls_self_signed_no_weak(fake_rdp):
    srv = fake_rdp(rdp.PROTOCOL_HYBRID)
    out = rdp.run_discover_tls("127.0.0.1", srv.port, timeout=5.0)
    assert isinstance(out, list)
    # fake server (modern Python) offers only 1.2/1.3 -> no weak protocols
    assert out == [] or all("{#RDP_TLS_PROTO}" in e for e in out)
