# 1d799b7b-8c5f-45bc-9a82-9c054e7d86ee — golden replay datasets

`Remote Thread Creation in Transaction Application Processes (AN1097-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown

* What it is: Data Manipulation: Runtime Data Manipulation. Adversaries modify data in memory or during runtime execution to alter transaction values, bypass checks, or steal retail cards (e.g., POS RAM scraping). They achieve this by injecting threads or acquiring process handles with write access targeting active business/database processes.
* Log Source Requirements: Sysmon Process Access events (Event ID 10) and Sysmon CreateRemoteThread events (Event ID 8).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. API calls requesting write handles and remote threads are natively monitored.
  - NIDS (Suricata + Zeek): NO. Host-local memory space operations.
* Log Sources Covered:
  - Sysmon Event ID 10 (process_access)
  - Sysmon Event ID 8 (create_remote_thread)
* Log Sources Missing / Unused:
  - None.

## Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'source_image not_regex .*\Q\MsMpEng.exe\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'target_image regex .*\Q\pos.exe\E$' — every other condition holds, so the stage gate rejects the events |

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
