# AN0271 — golden replay datasets

`Application Window Enumeration via Scripting Host (AN0271)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1010

* What it is: Application Window Discovery. Adversaries may enumerate open windows to identify active applications, discover visible user activity, or determine the presence of monitoring tools on a compromised host. On Windows, tools use Win32 API calls like EnumWindows() or GetForegroundWindow() to list all top-level window handles and their associated titles. This information is used for situational awareness, screenshot targeting, or keylogger targeting.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) and PowerShell Script Block Logs (Event ID 4104).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 captures spawning of PowerShell or scripting hosts. Script Block logging captures the actual content of window enumeration cmdlets.
    * Windows Security Logs: PARTIAL. Security logs EID 4688 captures command lines if enabled.
* Log Sources Covered:
    - Sysmon Event ID 1 (process_creation)
    - PowerShell Event ID 4104 (ps_script)
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
| `benign_1.jsonl` | 0 | near-miss value for 'script_block_text contains EnumWindows' — every other condition holds, so the stage gate rejects the events |
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
