# Phase 3 — 11501 import diff (validated via configuration.importcompare, 2026-05-25)

`templates/rdp-service/template_11501.yaml` was dry-run against the live 11501 with
`configuration.importcompare` (rules: createMissing+updateExisting true, deleteMissing **false**).

## Result: purely additive, nothing removed or changed
- **Macros added (5):** `{$RDP_HOSTNAME}`, `{$RDP_CERT_EXPIRY_WARN}`, `{$RDP_CERT_EXPIRY_CRIT}`, `{$RDP_CERT_ALLOW_SELFSIGNED}`, `{$RDP_NLA_ENFORCE}`. Existing `{$RDP_PORT}` unchanged.
- **Items added (15):** `rdp_check.py[cert,...]` + `rdp_check.py[tls-scan,...]` (EXTERNAL masters) and 13 DEPENDENT items (`rdp.ok`, `rdp.cert.*`, `rdp.tls.*`, `rdp.security_layer`, `rdp.nla_enforced`).
- **Triggers added (10):** nested under their first item (3 expiry, handshake-failed, NLA, legacy, CA hostname-mismatch, self-signed, weak-TLS) + existing down-trigger unchanged.
- **Existing `net.tcp.service` item, its down-trigger, and the `Service state` valuemap: unchanged.**

## Zabbix 7.0 schema lessons (hard-won; for the record)
1. **Triggers must be nested under their first item** (`items[].triggers[]`), NOT a template-level `triggers:` block — the latter throws an opaque `configuration.importcompare` APIError.
2. **`trends` is invalid on TEXT/CHAR items** — only set it on numeric (FLOAT/UNSIGNED).
3. **`BOOL_TO_DECIMAL` is parameterless** — do not emit an empty `parameters` list.
4. String equality in triggers works once nested: `last(/.../rdp.security_layer)="rdp"`.
5. `error_handler: DISCARD_VALUE` (and `CUSTOM_VALUE` + `error_handler_params`) on JSONPATH steps keeps dependents from going "unsupported" when the master is an error envelope.

## Required sequencing before the production import
**Deploy `rdp_check.py` to the Zabbix server AND the proxies first** (proxy 13905 → example-c; proxy 13938 → ts01-03; server → nvr/arc), else the two EXTERNAL items go "unsupported" (script not found) on every linked host until deployed. Then import 11501, then verify items populate.
