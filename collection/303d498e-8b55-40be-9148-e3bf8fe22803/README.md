# 303d498e-8b55-40be-9148-e3bf8fe22803 — golden replay datasets

`Collection - Data Access and Copy from Removable Media (AN1410)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

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


## Technique Breakdown

* What it is: Data from Removable Media. Adversaries search for and collect sensitive data stored on removable media devices (such as USB flash drives, external hard drives, or portable media) connected to the compromised host. They utilize scripting engines, command-line utilities (like `xcopy.exe` or `robocopy.exe`), or compression software to automate copying files from these mounted volumes (typically assigned letters like `D:\`, `E:\`, `F:\`, or `G:\` on Windows systems) to local staging folders before exfiltration.
* Log Source Requirements: Windows Security Event Log Event ID 4688 or Sysmon process creation logs (Event ID 1) capturing copy utility execution targeting removable drive letters.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs process details, capturing command lines copying or compressing files from non-system partition drive letters.
    * NIDS (Suricata + Zeek): NO. Removable media access is a local hardware and file-system operation.

## Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
