# Phase 0 — live-host validation results (2026-05-25)

> Note: hostnames here are **redacted to `example.*` placeholders**; this records the original validation run against the real fleet.

Probe: `scratch/probe_rdp.py` run from `zabbix.example.com` against the 6 hosts linked to template 11501, using each host's real `{$RDP_PORT}`.

## Per-host outcomes

| Host | Port | Result | security_layer | NLA | TLS | Cert |
|---|---|---|---|---|---|---|
| rdp-gw.example.com | 33899 | ✅ TLS cert | hybrid | **enforced** | TLSv1.2 | **CA (Let's Encrypt R13)** `CN=ts1.example.com`, 89d, self_signed=false |
| ts02.example-a.com | 49391 | ✅ TLS cert | hybrid | not enforced | TLSv1.2 | self-signed `CN=TS02.corp.local`, 101d |
| ts03.example-a.com | 49392 | ✅ TLS cert | hybrid | not enforced | TLSv1.3 | self-signed `CN=TS03.corp.local`, 180d |
| ts01.example-a.com | 49390 | ✅ negotiated | rdp (legacy) | — | none | `SSL_NOT_ALLOWED` (0x2) → no TLS |
| rdp.example-c.com | 43389 | ✅ negotiated | rdp (legacy) | — | none | `SSL_NOT_ALLOWED` (0x2) → no TLS |
| nvr.example-b.net | 46899 | unreachable from this node | — | — | — | — |
| arc.example-b.net | 43390 | unreachable from this node | — | — | — | — |

## Parser byte-offset confirmation (the key Phase-0 risk)
Captured real Connection-Confirm PDUs decode exactly:
- FAILURE: `03 00 00 13 0e d0 0000 1234 00 | 03 00 0800 02000000` → `neg_type=3, value=2`
- RSP:     `03 00 00 13 0e d0 0000 1234 00 | 02 1f 0800 01000000` → `neg_type=2, value=1`

`parse_x224_cc` slicing `data[11 : 5+li]` is correct against both real PDU types. ✅

## Test matrix status
| # | Feature | Status | Evidence |
|---|---|---|---|
| 1 | CA / publicly-trusted cert | ✅ real | rdp-gw — Let's Encrypt (issuer R13), self_signed=false, 89d |
| 2 | Self-signed cert | ✅ real | ts02, ts03 (correct expiry/issuer/self_signed/hostname_match) |
| 3 | NLA enforced (failure 0x5) | ✅ real | rdp-gw — `nla_enforced=true`, captured PDU value=5 |
| 4 | NLA not enforced | ✅ real | ts02, ts03 (`RDP_NEG_RSP`, ssl accepted) |
| 5 | Legacy / no-TLS | ✅ real | ts01, example-c (`SSL_NOT_ALLOWED`) |
| 6 | TLS version | ✅ real | TLSv1.2 (ts02), TLSv1.3 (ts03) |
| 7 | Negatives | ✅ | closed port (refused), non-RDP HTTP port (8180), wrong port (timeout) — all graceful |

**Engine verdict:** ALL 7 matrix rows validated against **real production RDP servers** — including CA (Let's Encrypt) cert and NLA-enforced (`0x5`) via `rdp-gw.example.com:33899`. Gate fully met.

## Fixtures captured (anonymized, for Phase 1 TDD)
- `tests/fixtures/ca_signed_cert.der` — synthetic CA-signed cert (`ts1.example.com` ← `Example Root CA`, self_signed=false).
- `tests/fixtures/selfsigned_cert.der` — synthetic self-signed cert (`TS02.corp.local`).
- `tests/fixtures/nla_enforced_failure.bin` — real `RDP_NEG_FAILURE` value=**5** (HYBRID_REQUIRED).
- `tests/fixtures/nla_optional_rsp.bin` — real `RDP_NEG_RSP` value=1 (SSL accepted).
- `tests/fixtures/nla_legacy_failure.bin` — real `RDP_NEG_FAILURE` value=2 (SSL_NOT_ALLOWED).

## ⚠ Pre-existing 11501 issues discovered (must inform the design)
1. **Per-host ports vary** (43389/46899/43390/49390/49391/49392) — handled fine by the `{$RDP_PORT}` macro; no change needed.
2. **5 of 6 hosts have NO interface** → the existing `net.tcp.service` simple-check is **UNSUPPORTED** on them (*"Check service item must have IP parameter or host interface specified"*). Only `rdp.example-c.com` (has an agent interface) reports. Implications:
   - **Tier A** (`net.tcp.service`) cannot work on interface-less hosts — it structurally requires an interface.
   - **Tier B** (external `rdp_check.py`) must target **`{HOST.HOST}`** (the technical name, which in this fleet equals the real DNS, e.g. `ts02.example-a.com`) rather than `{HOST.CONN}`, so it works without an interface. → **plan refinement:** master item key uses `{$RDP_HOSTNAME}` defaulting to `{HOST.HOST}`.
   - Recommend (with user): add a minimal interface to the 5 hosts so Tier A works too, OR accept external-check-only availability via `rdp.ok` on those hosts.
3. **Egress:** ts0x are behind proxy `13938`; example-c behind proxy `13905`; nvr/arc server-monitored. This node reached example-c + all ts0x, but not nvr/arc — final deployment should run `rdp_check` from the same node/proxy that monitors each host (egress parity, as designed).
