# 4928e1de-dfad-467d-97fb-ecddb53471b2 — golden replay datasets

`Pass the Ticket Kerberos Command Line (AN1000)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1550.003

* What it is: Use Alternate Authentication Material: Pass the Ticket. Adversaries hijack Kerberos Ticket Granting Tickets (TGT) or Service Tickets (TGS) to authenticate to remote resources without knowing the user's password. They inject stolen tickets into their local LSASS session (e.g., using Rubeus or Mimikatz). Detection focuses on identifying Kerberos Ticket requests (Event ID 4768/4769) containing anomalous or weak encryption types (like RC4-HMAC, 0x17 / 23), or process creations referencing ticket injection command parameters.
* Log Source Requirements: Windows Security Event Log Event ID 4768 (TGT requested) and Event ID 4769 (Service Ticket requested), or Sysmon process creation logs (Event ID 1).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Windows Security log audits Kerberos service requests. Sysmon Event ID 1 logs ticket injection tool parameters (e.g., rubeus.exe ptt). Wazuh parses these logs to trigger alerts.
  * NIDS (Suricata + Zeek): YES. Network sensors monitor Kerberos ticket request traffic and flag anomalous encryption algorithms.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Windows Security Log Event ID 4768 (security)
  - Windows Security Log Event ID 4769 (security)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Pass the ticket activity can be detected using process creation and security authentication logs.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'cmd_line contains ptt ' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | the field 'cmd_line' is absent entirely; an absent field is no-match for every operator, so the stage is never entered |

## Replaying

These datasets must be replayed onto **`replay-events-sysmon`**.
The topic name is not cosmetic: `NormalizedEventDeserializer` selects its parser
from the topic, and `inferSourceFromTopic` derives `NormalizedEvent.source` — the
value `rule.isApplicableTo` gates on. Replayed onto a topic that resolves to a
different source, this rule cannot fire at all.

```
replay --file true_positive_1.jsonl --topic replay-events-sysmon
```

## Determinism

Timestamps anchor at a fixed origin (`2026-03-02T09:00:00.000Z`), identities derive from the rule id, and event uids are content-derived.
Regenerating from an unchanged rule reproduces these files byte for byte.
