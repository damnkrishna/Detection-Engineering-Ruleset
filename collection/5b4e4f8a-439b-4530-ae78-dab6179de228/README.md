# 5b4e4f8a-439b-4530-ae78-dab6179de228 — golden replay datasets

`Collection - Anomaly Video Capture Library Load (AN0568)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1125

* What it is: Video Capture. Adversaries record video from the host webcam or screen using built-in software or custom malware commands. The collected video can be used to gather credentials, observe user actions, or perform espionage. On Windows endpoints, this is typically done by loading video capture libraries (like `avicap32.dll`, `capwin.dll`, or DirectShow/Media Foundation `mf.dll` wrappers) or executing CLI-based media tools (like `ffmpeg.exe`) targeting local camera devices.
* Log Source Requirements: Sysmon Library Load logs (Event ID 7) or process creation logs (Event ID 1).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 7 records process library loads, enabling detection when an unsigned application loads `avicap32.dll`. Sysmon Event ID 1 tracks command line execution.
    * NIDS (Suricata + Zeek): NO. Network sensors have no visibility into local system driver initialization or camera hardware actions.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'image_path not_regex .*\Q\obs64.exe\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'image_loaded regex .*\Q\avicap32.dll\E$' — every other condition holds, so the stage gate rejects the events |

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
