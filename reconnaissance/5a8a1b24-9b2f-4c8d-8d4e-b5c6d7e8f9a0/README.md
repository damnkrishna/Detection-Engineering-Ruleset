# 5a8a1b24-9b2f-4c8d-8d4e-b5c6d7e8f9a0 — golden replay datasets

`Suspicious System Information Gathering (AN2067)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1592
* What it is: Gather Victim Host Information. Adversaries query endpoints to discover host details, including operating system versions, patch levels, software versions, system configurations, and host names. Once a foothold is achieved, the Red Team executes system discovery commands to identify the host properties.
* Log Source Requirements: Endpoint process logs capturing command-line arguments.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 logs process creation and CLI arguments.
  - NIDS (Suricata + Zeek): NO. Host-local commands.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'parent_cmd_line not_contains C:\Windows\System32\drivers\etc\' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'cmd_line contains /S' — every other condition holds, so the stage gate rejects the events |

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
