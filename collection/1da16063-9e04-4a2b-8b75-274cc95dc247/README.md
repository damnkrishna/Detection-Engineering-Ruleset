# 1da16063-9e04-4a2b-8b75-274cc95dc247 — golden replay datasets

`Logon UI Suspicious DLL Load (AN0389-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown

* What it is: Input Capture: Credential API Hooking. Adversaries hook credential APIs (such as those within LSASS, LogonUI, or custom credential providers) to intercept and collect plain-text user passwords as they are entered during logon or password change procedures.
* Log Source Requirements: Sysmon Process Access logs (Event ID 10) and Sysmon Image Load logs (Event ID 7).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Memory injection access flags and DLL loads inside LSASS/LogonUI are natively audited.
  - NIDS (Suricata + Zeek): NO. Host-local system manipulation.
* Log Sources Covered:
  - Sysmon Event ID 10 (process_access)
  - Sysmon Event ID 7 (image_load)
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
| `benign_1.jsonl` | 0 | near-miss value for 'image_loaded not_starts_with C:\Program Files (x86)\' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'image_path regex .*\Q\logonui.exe\E$' — every other condition holds, so the stage gate rejects the events |

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
