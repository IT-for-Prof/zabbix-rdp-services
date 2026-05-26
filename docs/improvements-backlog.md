# RDP monitoring — issues & improvements backlog (audit 2026-05-26)

## ✅ RESOLVED in v0.2 (script + template imported & verified live 2026-05-26)
- **P1#1 timeout** → `{$RDP_TIMEOUT}=3` passed as `--timeout`; item timeouts 10s/15s. Unreachable now returns fast.
- **P1#2 connects** → subsumed by #1 (reachable checks already <1s; the timeout bound makes connect-count a non-issue).
- **P1#3 chain_valid decoupling** → chain-only verify; verified on rdp-gw (`chain_valid=1`, `hostname_match=0`). "CA hostname mismatch" trigger now reachable.
- **P2#4 unreachable alerting** → "RDP: check failing" trigger on `last(rdp.ok)=0` (covers interface-less nvr/arc), dep on port-down.
- **P2#5 nodata** → `nodata(rdp.ok,2h)` trigger.
- **P3#6 key size / signature** → `key_type`/`key_bits`/`sig_algorithm` items + weak-key (RSA<2048 / EC<256) and weak-sig (sha1/md5) triggers. Verified (ts02: RSA/2048/sha256).
- **P3#8 not-yet-valid** → `valid_now` item + "not currently valid" trigger.
- **P4#9 IPv6 parsing** → bracketed + bare IPv6 handled (unit-tested).
- **P4#10 trust-downgrade** → `{$RDP_CERT_EXPECT_CA}` macro + "not CA-trusted (expected CA)" trigger.
- **LLD** → `discover-tls` rule + `rdp.tls.weak[{#RDP_TLS_PROTO}]` item prototype (JS) + per-protocol trigger prototype. Verified: ts02 discovered TLSv1.0/1.1 → two per-proto Warnings; replaced the static rollup trigger.
- **Dependencies** → every cert/NLA/TLS trigger depends on port-down (+ "check failing" for cert-content) to suppress outage cascades.

## ⏳ DEFERRED / not code
- **P3#7 intermediate-chain expiry** — needs the full chain; Python 3.12 `ssl` has no `get_unverified_chain()` (3.13+). Would require extra work/deps; low value for short-lived LE leaves. Deferred.
- **P5#11** interface-less hosts (root cause of native availability gaps) + the `SSH service` mistag — host/owner config, surfaced.
- **P5#12** repo-publish redaction of customer hostnames before any GitHub push.

---
_Original audit below._



Audit inputs: live item states across all 6 linked hosts, proxy/server `Timeout` config, measured
check duration, estate RDP-host coverage, and best-practice research (Zabbix external checks; TLS cert).

## Current health (good)
- All 16 items **supported** (state 0) on all 6 hosts; data flowing. Reachable checks are **fast: 0.3–0.8 s**.
- ts02/ts03 = self-signed+NLA-not-enforced+weak-TLS (Warnings, self-signed suppressed ✓); ts01/example-c = legacy RDP (Warning ✓); nvr/arc = `unreachable` envelope.
- Coverage: all 3 DPI `rdp:*` hosts are linked to 11501. (`rdgw01.example-d.com` is `rdgw:443` = RDP-over-HTTPS via RD Gateway — different mechanism; its cert belongs to the web-service template, not this one.)

## P1 — correctness / operational
1. **Timeout layering on PROXY-A (`Timeout=4`)** vs item timeout (cert 30 s / tls-scan 60 s) and the script's 10 s-per-connect.
   PROXY-A monitors the only TLS hosts (ts0x). Reachable checks pass (<1 s), but a **slow/unreachable** host makes the script run up to ~30–40 s; if the proxy cap wins, the check is killed → the clean `{ok:false,unreachable}` envelope is lost and `rdp.ok` goes stale instead of 0.
   **Fix:** bound total script runtime well under the cap — add `{$RDP_TIMEOUT}` (default ~3 s) passed as `--timeout`, use a small per-connect timeout, and (see #2) fewer connects. Verify whether 7.0 honors the per-item timeout above the global on this proxy; align them.
2. **Too many TCP connects per check.** `cert` opens 3 sequential connections (NLA probe, cert grab, chain validate); `tls-scan` opens 4. **Fix:** derive NLA from the cert-grab negotiation response (1 fewer), and fold chain validation into the cert grab (verify-first, fall back to unverified) → `cert` down to 1 connect. Faster, fits the 4 s cap, removes partial-result loss.
3. **`chain_valid` / `hostname_match` coupling bug** → the "CA hostname mismatch" trigger is unreachable. `_chain_validates()` uses `create_default_context()` (verifies chain **and** hostname together), so `chain_valid=1` already implies hostname match. **Fix:** `chain_valid` = chain-only (`verify_mode=CERT_REQUIRED`, `check_hostname=False`); let `hostname_match` carry the name. Then a CA cert on the wrong name fires correctly.

## P2 — alerting gaps
4. **nvr/arc unreachability is not alerted.** Their `net.tcp.service` is unsupported (no interface), so both the "service down" and "handshake failed while up" triggers can't fire; the cert master returns `unreachable` but nothing alerts. **Fix:** add a trigger on sustained `rdp.ok=0` (independent of the port item), and/or give those 5 interface-less hosts an interface (root cause).
5. **No `nodata()` trigger.** If `rdp_check.py` is removed/breaks on a node, items go stale silently. **Fix:** add `nodata(/.../rdp.ok,2h)=1` (or on the raw master) → "RDP check not running".

## P3 — best-practice cert enrichment ([sources](https://www.globalsign.com/en/ssl-information-center/choosing-safe-key-sizes))
6. **No key size / signature algorithm checks.** Add `cert.key_bits` + `cert.sig_algorithm`; trigger on **RSA < 2048** or **SHA1/MD5 signature** (weak crypto). `cryptography` exposes both directly — easy win.
7. **Leaf-only expiry.** Intermediate/chain expiry not tracked (lower priority; LE leaves are short-lived anyway).
8. **Not-yet-valid cert** (`not_before` in the future / clock skew) not flagged. Minor.

## P4 — robustness / edge
9. **IPv6 host parsing.** `_split_target` (`count(":")==1`) mishandles IPv6 literals (none today; harden by parsing port from the right / bracket form).
10. **`{$RDP_CERT_EXPECT_CA}` trust-downgrade trigger** (from the earlier Q): per-host macro + `chain_valid=0` → alerts on any CA→self-signed/broken downgrade, even with self-signed allowed globally.

## P5 — process / estate hygiene (surfaced, owner decision)
11. Pre-existing: item mis-tagged `Application: SSH service`; 5 of 6 hosts have **no interface** (root cause of #4 and of native availability not working). 
12. Publishing the repo (for the proxy `install.sh` path) requires redacting customer hostnames/ports from `docs/phase0/*` and `docs/phase2/4*`.

## Tuning note (Zabbix 7.0)
7.0 uses async pollers (up to 1000 concurrent/poller) and per-item timeouts; with high timeouts, overprovision `StartPollers` and watch `zabbix[process,poller,avg,busy]` / `zabbix[queue]`. Current RDP load is negligible (<1 s checks), so no tuning needed beyond P1.
[Zabbix external check docs](https://www.zabbix.com/documentation/current/en/manual/config/items/itemtypes/external) · [7.0 what's new](https://www.zabbix.com/documentation/7.0/en/manual/introduction/whatsnew700)
