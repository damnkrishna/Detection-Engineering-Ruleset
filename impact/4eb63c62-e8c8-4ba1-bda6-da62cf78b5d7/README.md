# 4eb63c62-e8c8-4ba1-bda6-da62cf78b5d7 — golden replay datasets

`Registry Modification for System Logon Defacement via CLI (AN0229-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1491.001

* What it is: Internal Defacement. Adversaries modify the UI displays of internal systems or user endpoints to convey a message (such as ransom instructions, political statements, or compromise alerts). In Windows environments, this includes hijacking the system pre-logon warning message by altering registry values legalnoticecaption and legalnoticetext under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, or modifying the user desktop wallpaper registry keys under HKCU\Control Panel\Desktop\wallpaper.
* Log Source Requirements: Registry modification logs (Sysmon Event ID 13) and host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) tracking execution.
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 13 (Registry Set) is perfectly suited to track direct value modifications to defacement keys. Sysmon Event ID 1 captures command-line registry utilities or powershell cmdlets attempting these modifications.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 13 (registry_set)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Registry-based system defacement modifications can be detected using registry set and process creation logs.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'parent_image not_regex .*\Q\setup.exe\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'cmd_line contains reg' — every other condition holds, so the stage gate rejects the events |

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
