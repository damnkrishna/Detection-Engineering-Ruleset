# 33ab62a3-ba57-49bd-91af-c327fedba983 — golden replay datasets

`Disk Wiping and Partition Destruction Utilities via PowerShell Script Block (AN0384-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'script_block_text contains Clear-Disk' — every other condition holds, so the stage gate rejects the events |
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

* What it is: Disk Wipe. Adversaries destroy primary storage volumes, logical partitions, or Master Boot Records (MBR) on targeted systems, making the hosts completely unbootable and destroying all stored data. Under Windows, they abuse built-in utilities (like diskpart.exe, format.com, or fsutil.exe) to execute destructive routines (such as partition deletions, disk cleans, or volume dismounts). They may also use PowerShell storage cmdlets to modify or wipe disk layouts.
* Log Source Requirements: Endpoint logs capturing process creation and command line arguments (Sysmon Event ID 1 / Windows Security Event ID 4688) and PowerShell script block logs (Sysmon Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 captures the invocation of disk utility tools along with destructive CLI arguments. Sysmon Event ID 4104 (Script Block) is effective at catching PowerShell-based partition removal or disk clearing commands.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Disk wiping activity can be detected using process creation and PowerShell script block logs.

## Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
