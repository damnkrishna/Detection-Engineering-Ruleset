# 2a340a64-9fce-4edb-9d8d-d03bcf0635e6 — golden replay datasets

`Logon Warning Banner Registry Modification (AN0662-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown

* What it is: Defacement. Adversaries modify content hosted on web applications or system logon screens to convey messages or disrupt operations. This is accomplished by modifying local web root files or changing Windows Registry parameters.
* Log Source Requirements: Sysmon File Creation/Modification events (Event ID 11) and Sysmon Registry Set events (Event ID 13).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. File write activity inside web directories is captured by Sysmon EID 11. Registry adjustments are tracked by EID 13.
  - NIDS (Suricata + Zeek): NO. Host-local modification of assets.
* Log Sources Covered:
  - Sysmon Event ID 11 (file_event)
  - Sysmon Event ID 13 (registry_set)
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
| `benign_1.jsonl` | 0 | near-miss value for 'image_path not_regex .*\Q\svchost.exe\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'target_object regex .*\Q\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption\E$' — every other condition holds, so the stage gate rejects the events |

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
