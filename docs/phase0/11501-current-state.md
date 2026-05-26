# Template 11501 — current state (pulled via Zabbix MCP, 2026-05-25)

## Template
- **templateid:** 11501 · **name/host:** `Template App RDP Service` · status: template · uuid `2a5c7c018a2f491394a494c1a34dc016`
- No description, no discovery rules, no linked/parent templates.

## Macros (existing)
| Macro | Value | Note |
|---|---|---|
| `{$RDP_PORT}` | `43389` | **underscore** style; **non-standard port** (not 3389) |

## Items (existing)
| itemid | name | key | type | value_type | delay |
|---|---|---|---|---|---|
| 100182 | RDP service is running | `net.tcp.service[tcp,,{$RDP_PORT}]` | 3 (simple check) | 3 (unsigned) | 1m |

## Triggers (existing)
| triggerid | name | expression | priority |
|---|---|---|---|
| 29719 | RDP service is down on {HOST.NAME} | `last(.../net.tcp.service[...])=0` | 3 (Average) |

## Hosts linked to 11501 (test candidates)
| hostid | host | interface | expected profile |
|---|---|---|---|
| 11502 | rdp.example-c.com | agent dns=rdp.example-c.com:10050 | unknown — confirm in 0.4 |
| 13959 | nvr.example-b.net | none | unknown |
| 13960 | arc.example-b.net | none | unknown |
| 13987 | ts01.example-a.com | none | unknown |
| 13988 | ts02.example-a.com | none | unknown |
| 13989 | ts03.example-a.com | none | unknown |

RDP target = the host name on port `{$RDP_PORT}` (43389 unless a host overrides the macro). Most hosts have **no interface** — to confirm in Phase 4 whether the existing simple-check item is even supported on them.

## Reconciliation decisions for the improved template (update plan/spec)
1. **Reuse `{$RDP_PORT}` (underscore), keep default 43389** — do NOT introduce a parallel `{$RDP.PORT}`. New macros should follow the **underscore** convention: `{$RDP_CERT_EXPIRY_WARN}`, `{$RDP_CERT_EXPIRY_CRIT}`, `{$RDP_CERT_ALLOW_SELFSIGNED}`, `{$RDP_NLA_ENFORCE}`, `{$RDP_HOSTNAME}`.
2. **Reuse item 100182** as `rdp.available` (its key is exactly the planned native item) — do not duplicate.
3. **Reuse trigger 29719** as the port-down trigger (it is **Average**, not High — keep existing severity to avoid behavior change; revisit with user).
4. Trigger expression paths must use the real template name `Template App RDP Service`.
