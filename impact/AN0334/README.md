# AN0334 — golden replay datasets

`User Account Access Removal via CLI (AN0334)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1531

* What it is: Account Access Removal. Adversaries delete or disable local or domain user accounts (particularly administrator accounts) to lock out legitimate system administrators, prevent incident response recovery, or disrupt business operations. They execute account deactivations or deletions using command-line administrative tools (net.exe user <username> /delete or /active:no) or PowerShell cmdlets (Remove-LocalUser, Disable-LocalUser).
* Log Source Requirements: Endpoint logs capturing process creation and command line arguments (Sysmon Event ID 1 / Windows Security Event ID 4688) and PowerShell script block logs (Sysmon Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 logs CLI command parameters for user configuration utilities. Sysmon Event ID 4104 (Script Block) logs PowerShell script-based user management actions.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: User account access removal activity can be detected using process creation and PowerShell script block logs.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'cmd_line contains /delete' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'image_path regex .+\Q\net.exe\E$' — every other condition holds, so the stage gate rejects the events |

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
