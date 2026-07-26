# AN0342 — golden replay datasets

`Archive File Creation on Removable Media (AN0342)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1052

* What it is: Exfiltration Over Physical Medium. Adversaries copy stolen data directly to removable media devices (such as USB flash drives, external hard drives, or writeable CDs/DVDs) to bypass network filters and perimeter controls. Detections monitor for files being written or created on removable storage drive letters (e.g., E:\, F:\) or command-line commands copying files to these drives.
* Log Source Requirements: Endpoint logs capturing file creation events and process creation events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 11 (File Event) logs archive file creation paths (including drive letters) and Sysmon Event ID 1 (Process Creation) logs CLI copy commands targeting removable storage.
* NIDS (Suricata + Zeek): NO. Physical media exfiltration is entirely local and offline.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
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
| `benign_1.jsonl` | 0 | near-miss value for 'file_path regex .+\Q.zip\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | the field 'file_path' is absent entirely; an absent field is no-match for every operator, so the stage is never entered |

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
