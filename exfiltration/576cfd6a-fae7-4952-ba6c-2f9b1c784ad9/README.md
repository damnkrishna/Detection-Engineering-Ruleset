# 576cfd6a-fae7-4952-ba6c-2f9b1c784ad9 — golden replay datasets

`CLI Copy Command Targeting Removable Media (AN0616-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1052.001

* What it is: Exfiltration Over Physical Medium: Exfiltration over USB. Adversaries exfiltrate data by writing files directly to USB mass storage devices. To accelerate data collection and minimize interactive steps, they often execute automated command-line copy tools (like robocopy.exe, xcopy.exe) or custom scripts to scan and copy targeted files directly to plugged-in USB drives. Detections monitor file writes onto removable drive paths by these copy utilities or the process execution command lines.
* Log Source Requirements: Endpoint logs capturing file creation events and process creation events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 11 (File Event) logs when copy utilities write files to USB drive paths, and Event ID 1 (Process Creation) logs copy command-line executions targeting removable storage.
* NIDS (Suricata + Zeek): NO. Offline, local host actions.
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
| `benign_1.jsonl` | 0 | near-miss value for 'cmd_line contains  D:\' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'image_path regex .*\Q\xcopy.exe\E$' — every other condition holds, so the stage gate rejects the events |

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
