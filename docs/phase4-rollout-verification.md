# Phase 4 — production rollout verification (2026-05-26)

## Deployed
- `rdp_check.py` v0.1.0 installed (uv-managed Python 3.12 venv at `/opt/rdp_check`, script in
  externalscripts, `zabbix:zabbix` 0750) on: **zabbix.example.com (server)**, **PROXY-C (proxy 13905)**,
  **PROXY-A (proxy 13938)**. self-test OK on all three.
- Template **11501** imported via `configuration.import` (rules createMissing+updateExisting, deleteMissing=false).
  Live template now: **16 items, 10 triggers, 6 macros, 2 valuemaps** — matches `templates/rdp-service/template_11501.yaml`. Existing item/trigger/valuemap unchanged.

## End-to-end data flow verified (ts02.example-a.com, via proxy PROXY-A)
Forced check (`task.create` type 6) → proxy ran `rdp_check.py` → master JSON parsed → dependents populated:

| Item | Value |
|---|---|
| rdp.ok | 1 |
| rdp.security_layer | hybrid |
| rdp.nla_enforced | 0 |
| rdp.cert.self_signed | 1 |
| rdp.cert.subject_cn | TS02.corp.local |
| rdp.cert.days_to_expiry | 100 |
| rdp.tls.version | TLSv1.2 |
| rdp.tls.weak_count | 2 |

**Triggers behaved correctly:** raised `NLA not enforced` (Warning) and `weak TLS protocol offered` (Warning);
**self-signed suppressed** (`ALLOW_SELFSIGNED=1`); no false expiry/handshake alerts. Confirms the trust logic.

## Real findings surfaced by the new monitoring
- **ts02 / ts03**: self-signed RDP cert (internal CN), **NLA not enforced**, and weak TLS offered → Warnings.
- **rdp-gw** (test host, not linked): Let's Encrypt cert, NLA enforced, but offers TLSv1.0/1.1.
- **example-c / ts01**: legacy RDP Standard Security (no TLS) → Warning.

## Known/pre-existing (not caused by this work)
- `nvr.example-b.net` / `arc.example-b.net`: RDP port unreachable from server and proxies (their existing
  net.tcp.service item is also unsupported — no interface). External items will report `unreachable` until fixed.
- 5 of 6 hosts have no interface → native `net.tcp.service` (Tier A) stays unsupported on them; the external
  cert/NLA/TLS checks work regardless via `{HOST.HOST}`.
- Existing item mis-tagged `Application: SSH service` (left as-is; surfaced for the owner to fix).

## Status: COMPLETE — monitoring live and collecting on all reachable linked hosts.
Other linked hosts populate on their normal cadence (cert 1h, tls-scan 1d).
