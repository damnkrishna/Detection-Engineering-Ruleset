# 5e85a365-5176-40d3-9f3f-c84838a83d5a — golden replay datasets

`GUI Input Capture via PowerShell Script Block (AN1440-A)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1056.002
* What it is: Input Capture: GUI Input Capture. Adversaries prompt users for credentials by deploying spoofed GUI dialogs or windows. This is often accomplished via scripting hosts (like PowerShell or VB) using native Windows APIs (such as `Get-Credential` or `InputBox`) to trick users into typing their passwords.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) and PowerShell Script Block logging (Event ID 4104).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Script blocks and command-line execution parameters are captured natively.
  - NIDS (Suricata + Zeek): NO. Host-local script executions.
* Log Sources Covered:
  - Sysmon Event ID 4104 (ps_script)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

## Blind Spots & Tuning

- Authorized administrative scripts requesting user or service account credentials for execution context changes.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'script_block_text contains Password' — every other condition holds, so the stage gate rejects the events |
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
