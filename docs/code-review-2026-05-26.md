# Code review response (2026-05-26)

Reviewer (subagent) ran ruff, mypy --strict, bandit, pytest (24✓) — all clean. **No Critical issues.**
knip/biome N/A (pure Python). Findings and disposition:

## Fixed (committed + deployed + verified live)
- **#1 timeout headroom (Important)** — raised item timeouts (cert 10→15s, tls-scan 15→30s); combined with `{$RDP_TIMEOUT}=3` and #2, worst-case wall time is well within the item timeout. Unreachable hosts already short-circuit on the first connect (~3s).
- **#2 triple connection (Important)** — `run_cert` now **skips the chain-validation handshake when the cert is self-signed** (self-signed never chains). Common RDP case drops 3→2 connections. Verified: ts02 (self-signed) `chain_valid=0` with fewer connects; rdp-gw (CA) still `chain_valid=1`.
- **#3 IPv6 target parsing (Important)** — `_split_target` now rpartition-based: `host:port`, `ipv4:port`, and `ipv6:port` (the template always appends `:{$RDP_PORT}`) all parse correctly; bracketed `[ipv6]:port` still handled. No IPv6 hosts onboarded yet, but ready.
- **#4 dead trigger clause (Minor)** — removed the unreachable `="md5WithRSAEncryption"` clause (the code only emits hash names `sha1`/`md5`/...).
- **#5 HYBRID_EX mislabel (Minor)** — `grab_cert` now labels `PROTOCOL_HYBRID_EX` as `hybrid` (was falling through to `ssl`).

## Noted / accepted
- **#6 nodata vs check-failing interplay** — mitigated by the #1 timeout headroom; no flapping expected.
- **#7 cosmetic** — the baseline's `Application: SSH service` tag on the RDP item is left as-is (surfaced for the owner; not silently changed per the estate conventions).
- **#8 test gaps** — added an IPv6 parse test. The NLA-*enforced* socket path and weak-protocol *detection* path aren't unit-tested (the fake-RDP server only sends RSP / modern TLS), but both are **verified live**: NLA-enforced on rdp-gw, weak TLSv1.0/1.1 + LLD on ts02. Backlog: extend the fake server to send FAILURE/0x5 and pin `maximum_version=TLSv1_1`.
- `scratch/probe_rdp.py` retained intentionally as Phase-0 evidence.

Post-fix: ruff/mypy/bandit clean, 24 tests pass; script redeployed to server + both proxies; template re-imported; live values reconfirmed.
