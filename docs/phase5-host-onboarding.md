# Phase 5 — host onboarding + {HOST.CONN} targeting (2026-05-26)

## Added rdp-gw to RDP monitoring (the requested host)
- Host `RDP-GW` (hostid 10548, server-monitored, interface `dns=rdp-gw.example.com`) linked to template 11501.
- Host macros: `{$RDP_PORT}=33899`, `{$RDP_HOSTNAME}=ts1.example.com` (the cert CN — 33899 is a port-forward to the internal TS), `{$RDP_CERT_EXPECT_CA}=1`.
- **Verified live:** `rdp.ok=1`, `nla_enforced=1`, `security_layer=hybrid`, `chain_valid=1`, `hostname_match=1`, `self_signed=0`, `issuer=R13` (Let's Encrypt), `days_to_expiry=89`, `key_bits=2048`, `sig=sha256`. The CA-trusted + NLA-enforced showcase host.

## Connect-target redesign: {HOST.CONN}
- **Problem:** the template hardcoded the connect target as `{HOST.HOST}`, which only works when the host's technical name *is* its DNS. `RDP-GW`'s name ≠ DNS, so `{HOST.HOST}` was unresolvable.
- **Dead-end tried:** a `{$RDP_TARGET}` user-macro defaulting to `{HOST.HOST}` — **Zabbix does not expand a built-in macro stored as a user-macro value** (it passed through literally, e.g. `host="{HOST.CONN}"`). Reverted.
- **Fix:** keys use **`{HOST.CONN}`** directly (built-in macros expand in item keys). `{HOST.CONN}` is interface-based, so every host now needs an interface (see below). `{$RDP_HOSTNAME}` default changed to empty → the script falls back to the connect host (`args.hostname or host`), fixing a latent literal-`{HOST.HOST}` bug in hostname matching.

## Fixed the 5 interface-less hosts (the "fix hosts" gap)
- Added a DNS agent interface (`useip=0`, `dns=<host name>`, port 10050) to: nvr.example-b.net (13959), arc.example-b.net (13960), ts01/ts02/ts03.example-a.com (13987-89). example-c + rdp-gw already had interfaces.
- This makes **`{HOST.CONN}` resolve** for them (external cert/NLA/TLS) **and** makes the native `net.tcp.service` (Tier A availability) supported.
- **Interface binding:** simple-check items created before the interface existed had `interfaceid=0`; updated each host's `net.tcp.service` item to its new interface. Verified ts02 → `state=0, value=1` (UP). The others converge on their next poll.
- After interface changes, forced proxy `config_cache_reload` (ProxyConfigFrequency=600) so the active proxies (PROXY-C, PROXY-A) applied them immediately.

## Notes
- Adding an agent interface gives a (gray/unknown) Zabbix-agent availability indicator — cosmetic; no agent items exist, so it isn't actively polled.
- nvr/arc RDP ports remain unreachable on the network → `net.tcp.service=0` (down) + `rdp.ok=0` (check failing) now alert correctly (previously the items were unsupported/silent).
