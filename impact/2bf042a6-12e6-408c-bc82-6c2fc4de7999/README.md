# 2bf042a6-12e6-408c-bc82-6c2fc4de7999 — golden replay datasets

`Recovery Environment Disabling via PowerShell (AN0933-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'script_block_text contains Disable-ComputerRestore' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | the field 'script_block_text' is absent entirely; an absent field is no-match for every operator, so the stage is never entered |

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

* What it is: Inhibit System Recovery. Adversaries delete or remove built-in Windows recovery mechanisms—such as Volume Shadow Copies, backup catalogs, and automatic boot recovery options—to ensure the victim cannot easily restore their systems without paying a ransom. They execute these commands using native utilities or scripting APIs.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688, and PowerShell Script Block logging (Event ID 4104).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. All system command line invocations and scripting parameters are audited.
  - NIDS (Suricata + Zeek): NO. Host-local recovery controls.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.

## Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
