# 59a35e4d-080c-43f1-b1e6-b040cf6e3e5c — golden replay datasets

`Suspicious Windows Command Shell Execution (AN0578)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1059.003

* What it is: Command and Scripting Interpreter: Windows Command Shell. Adversaries use `cmd.exe` or batch files (`.bat`, `.cmd`) to interact with the system, execute programs, or launch subsequent scripts. Because `cmd.exe` is ubiquitous and heavily utilized by the OS, attackers frequently use it to blend in.
* Log Source Requirements: Process creation logs (Sysmon Event ID 1 / Windows Security Event ID 4688).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures every invocation of `cmd.exe`, including full command-line parameters (like `/c` or `/k`) and the parent process.
    * NIDS (Suricata + Zeek): NO. Command shell usage is strictly a local host activity.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'parent_image regex .*\Q\winword.exe\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'image_path regex .*\Q\cmd.exe\E$' — every other condition holds, so the stage gate rejects the events |

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
