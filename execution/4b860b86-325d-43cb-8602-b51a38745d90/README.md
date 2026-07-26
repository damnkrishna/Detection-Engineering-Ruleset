# 4b860b86-325d-43cb-8602-b51a38745d90 — golden replay datasets

`DLL Side-Loading File Drop (AN0577-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1574.001

* What it is: Hijack Execution Flow: DLL Side-Loading. Adversaries abuse the Windows search order for shared libraries (DLLs) to execute malicious payloads. By copying a legitimate, signed system binary (like calc.exe or notepad.exe) into a user-writable directory (like %TEMP% or C:\Users\Public\) and placing a malicious DLL named after a required system dependency in that same directory, the application will load the malicious DLL instead of the legitimate one from System32.
* Log Source Requirements: Endpoint logs capturing image/library loading events and file write events in user-writable paths.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 7 (Image Load) logs when DLLs are loaded by system binaries running from non-standard paths, and Event ID 11 (File Event) logs when DLLs are written to these paths.
* NIDS (Suricata + Zeek): NO. Local host activity.
* Log Sources Covered:
  - Sysmon Event ID 7 (image_load)
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
| `benign_1.jsonl` | 0 | near-miss value for 'file_path contains \AppData\Local\Temp\' — every other condition holds, so the stage gate rejects the events |
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
