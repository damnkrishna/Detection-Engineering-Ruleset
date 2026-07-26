# 3520f684-7d35-48a7-8e40-62601ad4d27c — golden replay datasets

`Collection - Archive File Written to Remote UNC Share (AN0194)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'image_path not_regex .*\Q\System32\wbengine.exe\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'file_path regex .*\Q.zip\E$' — every other condition holds, so the stage gate rejects the events |

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


## Technique Breakdown

* What it is: Data Staged: Remote Data Staging. Adversaries copy collected data to a centralized remote staging location (such as a shared folder or storage server inside the compromised network) prior to exfiltration. Staging data remotely helps them aggregate logs or files from multiple systems before transmitting them out-of-band. On Windows systems, this is detected by identifying processes writing data archives (like `.zip`, `.7z`, `.rar`) to remote UNC paths (e.g. `\\server\share\`) or mapping staging drives.
* Log Source Requirements: Sysmon File Creation logs (Event ID 11) or process creation logs (Event ID 1) capturing network drive mappings.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 11 captures file creations targeting UNC paths. Event ID 1 captures command parameters mapping drives (like `net.exe use`). Wazuh manages alerting.
    * NIDS (Suricata + Zeek): YES. Network logs capture SMB file write operations over ports 445/139, which confirms network staging.

## Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
