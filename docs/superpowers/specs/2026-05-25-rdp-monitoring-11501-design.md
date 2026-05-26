# RDP service monitoring — design spec

- **Date:** 2026-05-25
- **Status:** Approved design → ready for implementation plan
- **Project dir:** `/opt/zabbix-rdp-services` (new standalone project, mirrors `zabbix-webservices`)
- **Source / reference:** `/opt/zabbix-webservices` (patterns + reusable code only — not edited)
- **Target template:** `Template App RDP Service`, **templateid 11501** on `zabbix.example.com`
- **Zabbix:** 7.0; MCP server at `http://127.0.0.1:8180/mcp`

## Goal

Improve Zabbix template **11501 in place** with best-practice RDP monitoring and a
working RDP **certificate** check, validated against real hosts before rollout. All
deliverables (script, template export, deploy, docs) live in `/opt/zabbix-rdp-services`.

## Non-goals

- Not editing `zabbix-webservices`/`web_check.py` (used as reference only).
- Not authenticating to RDP (no credentials; we read the cert from the TLS handshake
  that precedes CredSSP, and never complete CredSSP/NLA auth).
- Not building an RDP client or session recorder.

## Why not a plain TLS check / Agent 2 web-cert

RDP presents its X.509 certificate **only after** an X.224 / RDP "negotiation" exchange
in which the client first announces `PROTOCOL_SSL` / `PROTOCOL_HYBRID`. Zabbix Agent 2's
`web.certificate.get` and the "Website certificate by Zabbix agent 2" template perform a
**direct** TLS handshake with no RDP negotiation, so against TCP 3389 they time out /
return no certificate. A correct RDP cert check therefore requires the negotiation —
either `openssl s_client -starttls rdp` (OpenSSL ≥1.1.1) or a small Python handshake.

**Library survey (rejected as dependencies):**

| Package | Verdict |
|---|---|
| [pyrdp](https://github.com/GoSecure/pyrdp) | GPLv3 + heavy MITM toolkit — cannot ship cleanly |
| [rdpy](https://github.com/citronneur/rdpy) | Python 2 / Twisted, unmaintained, GPLv3 |
| [aardwolf](https://pypi.org/project/aardwolf/) | Full async client; pulls asysocks/asyauth/unicrypto — overkill |

The negotiation we need is ~30 lines of well-specified [MS-RDPBCGR] PDUs. We hand-roll it
with stdlib `socket`/`ssl` + `cryptography` (already used by the reference `check_cert`),
using aardwolf's/rdpy's `x224.py` only as a byte-layout reference. No new dependency, no
GPL.

## Locked decisions

1. **Scope:** improve template **11501 in place** — keep its existing availability items,
   add cert validity/expiry, NLA/CredSSP enforcement, TLS posture, standardized
   availability/latency.
2. **Code home:** new standalone `scripts/externalscripts/rdp_check.py` in this project.
3. **Mechanism:** hand-rolled X.224 negotiation + stdlib `ssl` + `cryptography`. No RDP lib.
4. **Trust model:** CA / publicly-trusted certs (e.g. Let's Encrypt, internal CA) get full
   validation; self-signed certs suppress the self-signed & hostname-mismatch alerts by
   default but **still** get expiry / NLA / TLS / handshake checks.
5. **Validation gate:** Phase 0 of the plan = pull hosts linked to 11501 via the Zabbix MCP
   + run a live probe; all features (#1–#7 below) must pass before any template work; an
   end-to-end check on 2–3 hosts (#8) precedes full rollout.
6. **Deploy:** this project ships its own `install.sh` mirroring `zabbix-webservices`.

## Architecture — three tiers

All checks run from the Zabbix server/proxy that already monitors the host (egress parity,
same as the web-service template).

- **Tier A — availability (scriptless, native, ~1m):**
  `net.tcp.service[tcp,{$RDP.PORT}]` (up/down) and `net.tcp.service.perf[tcp,{$RDP.PORT}]`
  (connect latency).
- **Tier B — cert + security (script, ~1h):** one `rdp_check.py cert <host:port>` master
  item emits a single JSON blob → JSONPath **dependent items** (no extra network calls).
- **Tier C — TLS posture (script, daily):** `rdp_check.py tls-scan` walks TLS versions over
  the X.224 preamble (analogue of the web template's Layer 5). Optional LLD for findings.

## `rdp_check.py` — behavior

CLI subcommands (argparse, mirroring `web_check.py`): `cert`, `tls-scan`, `self-test`
(offline smoke). Output is JSON on stdout; failures use the project's standard
`error_envelope(error_code, message, ...)` so triggers can tell "unreachable" / "not RDP" /
"legacy no-TLS" apart from real cert problems.

### `cert <host:port>` flow

1. Open TCP socket to `host:port` (`{$RDP.PORT}` default 3389).
2. **NLA probe:** send TPKT + X.224 Connection Request carrying `RDP_NEG_REQ` with
   `requestedProtocols = PROTOCOL_SSL` only (`0x00000001`). Read the Connection Confirm:
   - `RDP_NEG_FAILURE` with `HYBRID_REQUIRED_BY_SERVER` (`0x5`) → `nla_enforced = true`.
   - `RDP_NEG_RSP` with `selectedProtocol = SSL` → `nla_enforced = false`.
   - `selectedProtocol = RDP` (`0x0`) or `SSL_NOT_ALLOWED_BY_SERVER` (`0x2`) /
     `SSL_CERT_NOT_ON_SERVER` (`0x3`) → legacy **RDP Standard Security**, no TLS cert.
3. **Cert grab:** new socket, X.224 CR with `requestedProtocols = HYBRID|SSL` (`0x3`); read
   `selectedProtocol`; then `ssl`-wrap (verification off, capture binary peer cert). The
   server presents its cert during the TLS handshake that precedes CredSSP, so we read it
   without completing NLA auth. Parse with `cryptography` (reuse `check_cert` logic).
4. Emit JSON; on any failure, `error_envelope`.

### `cert` JSON output schema

```json
{
  "host": "host.example.com", "port": 3389,
  "security_layer": "hybrid",          // rdp | ssl | hybrid
  "nla_enforced": true,
  "tls": { "version": "TLSv1.2", "cipher": "ECDHE-RSA-AES256-GCM-SHA384" },
  "cert": {
    "subject_cn": "HOST.example.com",
    "issuer": "R3 / Let's Encrypt",
    "not_before": "2026-04-01T00:00:00Z",
    "not_after":  "2026-06-30T00:00:00Z",
    "days_to_expiry": 36,
    "self_signed": false,
    "hostname_match": true,            // SAN/CN vs {$RDP.HOSTNAME}
    "chain_valid": true                // verified against node trust store (best-effort)
  },
  "ts": "2026-05-25T12:00:00Z"
}
```

Legacy RDP-Standard hosts: `security_layer="rdp"`, `cert=null`, no crash.

**Caveat on `chain_valid`:** "valid" = chains to the *monitoring node's* trust store.
Public CAs (Let's Encrypt) validate anywhere; an internal CA validates only on nodes that
trust it. Documented so trigger tuning is predictable.

## Template 11501 — items

Confirm existing items via MCP first; **keep** current availability items (rename/standardize
only if needed) and **add** the below.

| Item key | Source | Type |
|---|---|---|
| `rdp.available` | `net.tcp.service[tcp,{$RDP.PORT}]` | native, ~1m |
| `rdp.latency`   | `net.tcp.service.perf[tcp,{$RDP.PORT}]` | native, ~1m |
| `rdp.cert.raw`  | `rdp_check.py cert {HOST.CONN}:{$RDP.PORT}` | script master, ~1h |
| `rdp.cert.days_to_expiry` | JSONPath `$.cert.days_to_expiry` | dependent |
| `rdp.cert.not_after` / `.issuer` / `.subject_cn` | JSONPath | dependent |
| `rdp.cert.self_signed` / `.hostname_match` / `.chain_valid` (0/1) | JSONPath | dependent |
| `rdp.tls.version` / `rdp.tls.cipher` | JSONPath | dependent |
| `rdp.security_layer` / `rdp.nla_enforced` | JSONPath | dependent |
| `rdp.tls.weak_count` (+ `rdp.tls.weak_findings`) | `rdp_check.py tls-scan` | script master, daily |
| `rdp.ok` | JSONPath `$.ok` (envelope health) | dependent |

## Macros

| Macro | Default | Purpose |
|---|---|---|
| `{$RDP.PORT}` | `3389` | RDP TCP port |
| `{$RDP.HOSTNAME}` | `{HOST.CONN}` | name to match cert SAN/CN against |
| `{$RDP.CERT.EXPIRY_WARN}` | `21` | days → Warning |
| `{$RDP.CERT.EXPIRY_CRIT}` | `7` | days → High |
| `{$RDP.CERT.ALLOW_SELFSIGNED}` | `1` | 1 = self-signed is normal; 0 = self-signed → Warning |
| `{$RDP.NLA.ENFORCE}` | `1` | 1 = alert when NLA not enforced |

## Triggers — trust logic

**Always fires (trust-independent):**

- `rdp.available = 0` → **High** (port down).
- `rdp.cert.days_to_expiry < 0` → **High** (expired).
- `rdp.cert.days_to_expiry < {$RDP.CERT.EXPIRY_CRIT}` → **High**;
  `< {$RDP.CERT.EXPIRY_WARN}` → **Warning** (expiring soon).
- Handshake/cert fetch fails **while `rdp.available = 1`** → **Average** ("TLS broken" ≠
  "host down" — gated on port being up to avoid duplicate alarms).
- `rdp.nla_enforced = 0 and {$RDP.NLA.ENFORCE} = 1` → **Warning** (NLA not enforced).
- `rdp.security_layer = "rdp"` → **Warning** (legacy RDP Standard, no TLS).
- `rdp.tls.weak_protocols` shows TLS ≤1.1 → **Warning** (daily).

**Trust-gated (the Let's-Encrypt-vs-self-signed requirement):**

- **CA / publicly-trusted** (`rdp.cert.chain_valid = 1`): full validation —
  `rdp.cert.hostname_match = 0` → **Average**; chain invalid → **Average**.
- **Self-signed** (`rdp.cert.self_signed = 1`): the "self-signed" and "hostname mismatch"
  triggers are **suppressed while `{$RDP.CERT.ALLOW_SELFSIGNED} = 1`** (default). Expiry,
  NLA, TLS-posture, and handshake triggers **still apply**. Set the macro to `0` per host
  to make self-signed itself a **Warning**.

Net effect: good certs validated normally; for self-signed we ignore the self-signed-ness
but keep doing every other check.

## Project layout (mirrors `zabbix-webservices`)

```
/opt/zabbix-rdp-services/
  scripts/externalscripts/rdp_check.py    # cert / tls-scan / self-test
  scripts/deploy/install.sh               # uv + pinned venv, drops rdp_check.py in ExternalScripts
  scripts/deploy/requirements.lock        # cryptography (pinned)
  templates/rdp-service/template_11501.yaml  # improved 11501 export (source of truth)
  tests/                                  # unit tests incl. recorded-bytes negotiation fixtures
  docs/                                   # architecture, validation, this spec
```

Deploy reuses the `zabbix-webservices` install pattern but in its **own** path
`/opt/rdp_check` (isolated Python + venv), `cryptography` pinned, script owned
`zabbix:zabbix` mode `0750`, `self-test` smoke check. Independent of any `web_check`
install on the node.

## Phase 0 — empirical validation gate (must pass before ANY production code)

**Hard gate.** No production code is written until this passes — not `rdp_check.py`, not the
template YAML, not triggers, not `install.sh`. The *only* code permitted in Phase 0 is a
**disposable test probe** (just enough X.224 negotiation + TLS cert read to exercise the
features below); it is thrown away / refactored into the real script only after the gate
passes. The implementation plan MUST sequence Phase 0 before every other phase.

Pull hosts linked to 11501 via the Zabbix MCP; probe a representative sample with the
throwaway probe. Every feature must produce correct output against **real hosts** first.

| # | Feature | Real-host test → expected |
|---|---|---|
| 1 | Cert grab — CA cert | Let's Encrypt/internal-CA host → correct expiry/issuer/SAN, `chain_valid=1`, `self_signed=0` |
| 2 | Cert grab — self-signed | default Windows host → `self_signed=1`, real expiry, no crash |
| 3 | NLA enforced | NLA-required host → `nla_enforced=1` (failure `0x5`) |
| 4 | NLA optional | NLA-off host → `nla_enforced=0` |
| 5 | Legacy / no-TLS | RDP-Standard host (if any) → `security_layer="rdp"`, `cert=null`, graceful |
| 6 | TLS version + posture | negotiated version correct; weak-proto detection on a TLS1.0/1.1 host |
| 7 | Negatives | closed port → error envelope; non-RDP TCP service on the port → graceful X.224 parse error |
| 8 | End-to-end | link enhanced 11501 to 2–3 hosts → items populate, triggers behave → only then roll out |

Steps #1–#7 gate building the template; #8 gates full rollout.

## Error handling / edge cases

- Closed port / timeout → `error_envelope("unreachable", ...)`; Tier A also flags it.
- Non-RDP service on the port (e.g. a web port) → TPKT/X.224 parse fails →
  `error_envelope("not_rdp", ...)`.
- Legacy RDP Standard (no TLS) → `security_layer="rdp"`, `cert=null` (a finding, not an error).
- Truncated/odd negotiation responses → defensive parsing, bounded reads, socket timeout.

## Reference constants ([MS-RDPBCGR])

- Protocols: `PROTOCOL_RDP=0x0`, `PROTOCOL_SSL=0x1`, `PROTOCOL_HYBRID=0x2`,
  `PROTOCOL_HYBRID_EX=0x8`.
- Negotiation failure codes: `SSL_REQUIRED_BY_SERVER=0x1`, `SSL_NOT_ALLOWED_BY_SERVER=0x2`,
  `SSL_CERT_NOT_ON_SERVER=0x3`, `INCONSISTENT_FLAGS=0x4`, `HYBRID_REQUIRED_BY_SERVER=0x5`,
  `SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER=0x6`.
- TPKT: `0x03 0x00 <len_be:2>`. X.224 CR PDU `0xE0…`, CC PDU `0xD0…`.
  `RDP_NEG_REQ` type `0x01`, `RDP_NEG_RSP` type `0x02`, `RDP_NEG_FAILURE` type `0x03`
  (each: type, flags, `length=0x0008` LE, 4-byte LE payload).

## Open items to resolve during Phase 0

- Exact current item/macro/trigger set on 11501 (read via MCP; reconcile keys).
- Whether to keep a single combined `cert` item or split a fast `cert` (Tier B) from a
  daily `tls-scan` (Tier C) on these specific hosts.
- Confirm monitoring nodes' OpenSSL/Python can negotiate the TLS versions RDP hosts offer.
