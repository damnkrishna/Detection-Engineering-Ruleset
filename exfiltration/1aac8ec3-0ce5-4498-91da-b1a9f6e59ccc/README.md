# 1aac8ec3-0ce5-4498-91da-b1a9f6e59ccc — golden replay datasets

`Exfiltration - Command-Line Cloud Storage Sync Execution (AN1571)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown

* What it is: Exfiltration Over Web Service: Exfiltration to Cloud Storage. Adversaries exfiltrate data by uploading it directly to public cloud storage providers (such as Mega, Dropbox, OneDrive, Azure Blob, or AWS S3) using command-line synchronization tools (like `rclone.exe`, `megacmd.exe`) or administrative CLI tools (`aws.exe`, `az.exe`). Because cloud storage domains are frequently accessed for legitimate business, these connections are rarely blocked at the perimeter. Host-based process creation and command line parameters are critical to spot these unauthorized tools.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) capturing cloud sync clients and CLI commands.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 records the execution of cloud clients (like `rclone.exe`) along with sync/copy arguments. Wazuh parses and alerts.
    * NIDS (Suricata + Zeek): YES. Network logs track large data transfers to cloud service provider domains, but host logs are needed to verify the specific application context.

## Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'cmd_line contains  sync ' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'image_path regex .*\Q\rclone.exe\E$' — every other condition holds, so the stage gate rejects the events |

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
