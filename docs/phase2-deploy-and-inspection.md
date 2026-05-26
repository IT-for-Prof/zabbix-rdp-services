# Phase 2 — deploy + deep inspection (2026-05-26)

## Environment (Zabbix server = zabbix.example.com, via SSH as root)
- Zabbix **7.0.26**; `ExternalScripts=/usr/lib/zabbix/externalscripts`; `uv 0.11.14`.
- Sibling `web_check` deployed at `/opt/web_check` (venv Python 3.12.13). DPI checker deployed as `/opt/dpi-probe/dpi_probe` symlinked into externalscripts.
- System python is 3.6.8 → uv-managed 3.12 is required (as designed).

## Deployment — DONE on the server, verified live
- `/opt/rdp_check/venv` (uv Python 3.12.13) + pinned `requirements.lock` (cryptography 48).
- `/usr/lib/zabbix/externalscripts/rdp_check.py` — owner `zabbix:zabbix`, mode `0750`, shebang → `/opt/rdp_check/venv/bin/python`.
- `self-test` (as zabbix) → `{"ok":true,...}`; `--version` → `0.1.0`.
- **Live, run as the `zabbix` user:**
  - `rdp-gw.example.com:33899` → CA cert (Let's Encrypt R13), `nla_enforced=true`, TLSv1.2, `chain_valid=true`, `hostname_match=true`.
  - `tls-scan` rdp-gw → offers **TLSv1.0 + TLSv1.1** → `weak_count=2` (real finding).
  - `nvr`/`arc` → `unreachable` even from the server (their existing item is also unsupported — pre-existing).

## Deployment — PENDING on the proxies (needed for the linked hosts)
External checks run on the node that monitors the host. The 6 linked hosts:
- example-c → proxy **13905 (PROXY-C, active)**
- ts01/ts02/ts03 → proxy **13938 (PROXY-A, active)**
- nvr/arc → server (unreachable anyway)

Both proxies are **active-mode** (connect inbound; not SSH-reachable by address from here). `rdp_check.py` must be installed on **PROXY-C** and **PROXY-A** — run `scripts/deploy/install.sh` on each (once the repo is published), or copy-deploy as we did on the server. Until then, the two external items will be "unsupported" on proxy-monitored hosts.

## Deep inspection findings
**Informativeness — good, with one fix applied:**
- Output is rich: issuer, expiry (+`units: days`), self-signed/hostname/chain flags, TLS version+cipher, security layer, NLA, plus the raw JSON master for debugging, and `tls-scan` weak-protocol findings.
- **Applied:** `Yes/No` valuemap on the boolean items (`rdp.ok`, `self_signed`, `hostname_match`, `chain_valid`, `nla_enforced`) so the UI shows Yes/No, not 0/1. (importcompare-validated.)

**Dependencies:**
- Item dependencies (external master → 13 JSONPath dependents): correct, validated.
- Trigger dependencies: **recommended addition** — make the cert/NLA/TLS triggers depend on `RDP service is down` (and the cert-content ones also on `TLS handshake/cert fetch failed while port up`) so an outage raises one root-cause alert, not a cascade. Not yet applied (changes alert topology — pending your OK).

## Pre-existing issues to surface (not silently fixed, per conventions)
1. Existing item `net.tcp.service` carries a mis-pasted tag `Application: SSH service` on an RDP template.
2. 5 of 6 linked hosts have **no interface** → the existing availability item is **unsupported** today; our external check sidesteps this via `{HOST.HOST}`.
3. `nvr.example-b.net` / `arc.example-b.net` are unreachable on their RDP ports from the server.
