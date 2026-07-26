# 489d52cd-31ba-4725-9b05-e22fc4ce6923 — golden replay datasets

`Accessibility Features Registry Debugger Configuration (AN0094-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1546.008
* What it is: Event Triggered Execution: Accessibility Features. Windows accessibility tools (e.g., Sticky Keys sethc.exe, Utility Manager utilman.exe, On-Screen Keyboard osk.exe, Magnifier magnify.exe) can be launched using key combinations before a user logs in. Adversaries exploit this behavior by replacing these binary files with a command prompt (cmd.exe) or modifying the Image File Execution Options (IFEO) registry keys to assign a "Debugger" string pointing to a shell.
* Log Source Requirements: Endpoint logs capturing process creation events and registry modifications.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures accessibility binaries spawning command interpreters. Sysmon Event ID 13 (Registry Value Set) tracks direct registry overrides.
  - NIDS (Suricata + Zeek): NO. Host-local logon screen interactions.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
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
| `benign_1.jsonl` | 0 | near-miss value for 'target_object contains \Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | the field 'target_object' is absent entirely; an absent field is no-match for every operator, so the stage is never entered |

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
