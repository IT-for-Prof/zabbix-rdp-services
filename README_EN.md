# zabbix-rdp-services

> 🇷🇺 [Читать по-русски](README.md)

Best-practice **RDP monitoring** for Zabbix 7.0 — certificate, NLA enforcement, TLS
posture, and availability — delivered as an external check plus an improved
`Template App RDP Service` (templateid 11501). Maintained by [IT for Prof](https://itforprof.com).

## Why a script

RDP presents its X.509 certificate only **after** an X.224/RDP negotiation
(`PROTOCOL_SSL`/`PROTOCOL_HYBRID`). A plain TLS handshake (e.g. Zabbix Agent 2's
`web.certificate.get`) does **not** work against port 3389. So `rdp_check.py`
hand-rolls the [MS-RDPBCGR] negotiation in pure Python (stdlib `socket`/`ssl` +
`cryptography`, no third-party RDP library), then reads the cert / NLA / TLS.

## What it monitors

| Tier | How | Items |
|------|-----|-------|
| Availability | native `net.tcp.service[tcp,,{$RDP_PORT}]` | port up + latency |
| Cert / NLA / security | `rdp_check.py cert` (1h) → JSON master + JSONPath dependents | expiry, issuer, self-signed, hostname-match, chain-valid, key type/bits, sig alg, valid-now, TLS version/cipher, security layer, NLA enforced |
| TLS posture | `rdp_check.py tls-scan` (1d) + LLD `discover-tls` | weak-protocol count + per-protocol discovered items/triggers |

**Trust logic:** CA/publicly-trusted certs are validated fully (chain + hostname +
expiry); self-signed certs suppress the self-signed/mismatch alerts by default
(`{$RDP_CERT_ALLOW_SELFSIGNED}=1`) but still get expiry/NLA/TLS/handshake checks.
Triggers depend on port-down + "check failing" so an outage raises one root cause.

## Layout

```
scripts/externalscripts/rdp_check.py   # cert / tls-scan / discover-tls / self-test
scripts/deploy/install.sh              # uv venv at /opt/rdp_check + drop into ExternalScripts
templates/rdp-service/template_11501.yaml          # improved 11501 (source of truth)
templates/rdp-service/template_11501_baseline.yaml # untouched original
tests/                                 # pytest: byte/cert fixtures + fake-RDP server
docs/                                  # spec, plan, validation, audit, review, deploy notes
```

## Deploy

Run on the Zabbix **server and every proxy** that monitors RDP hosts (egress parity):

```
sudo sh scripts/deploy/install.sh          # builds /opt/rdp_check venv, installs rdp_check.py
```

Then import `templates/rdp-service/template_11501.yaml` (createMissing + updateExisting,
**deleteMissing: false**); review the `configuration.importcompare` diff first.

## Macros

| Macro | Default | Purpose |
|---|---|---|
| `{$RDP_PORT}` | `3389` | RDP TCP port |
| `{$RDP_TIMEOUT}` | `30` | total time budget per check (item `timeout` must exceed it) |
| `{$RDP_HOSTNAME}` | *(empty)* | cert SAN/CN to match; empty = use the connect host |
| `{$RDP_CERT_EXPIRY_WARN}` / `_CRIT` | `21` / `7` | days-to-expiry thresholds |
| `{$RDP_CERT_ALLOW_SELFSIGNED}` | `1` | 1 = self-signed is normal; 0 = alert |
| `{$RDP_CERT_EXPECT_CA}` | `0` | 1 = alert when not CA-trusted (chain invalid) |
| `{$RDP_CERT_MIN_RSA_BITS}` / `_EC_BITS` | `2048` / `256` | weak-key thresholds |
| `{$RDP_NLA_ENFORCE}` | `1` | 1 = alert when NLA is not enforced |

## Notes / gotchas (learned the hard way)

- Item keys use **`{HOST.CONN}`** directly — Zabbix does **not** expand a built-in
  macro stored as a *user-macro value*. Every host therefore needs an interface.
- Triggers are **nested under their first item** (`items[].triggers[]`); a
  template-level `triggers:` block is rejected on import in 7.0.
- `cryptography >= 42` for the `not_valid_*_utc` accessors (shimmed for 41).
- TLS-version probing must suppress `DeprecationWarning` (TLSv1/1.1) or the warning
  text leaks into stdout and corrupts the JSON the dependent items parse.
- RD Gateway (RDP-over-HTTPS:443) is **not** this template's job — use the
  web-service template for its cert/TLS, and monitor internal TS hosts directly.

Dev: `pip install -r tests/requirements-test.txt`; `pytest tests`; `ruff check scripts tests`; `mypy --strict scripts/externalscripts/rdp_check.py`.

## Author

**Konstantin Tyutyunnik** — [IT for Prof](https://itforprof.com) · License: MIT
