# 4df5d95f-6387-467b-b1a1-10ce3f19f2fc — golden replay datasets

`File Copy to Administrative Shares (AN0516-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1570

* What it is: Lateral Tool Transfer. Adversaries may transfer tools or other files from one system to another inside a compromised environment (lateral movement). They often copy utilities, scripts, or credential access tools to administrative network shares (such as C$, ADMIN$, IPC$) on a remote machine using built-in command-line copy/move tools (e.g. copy, move, xcopy.exe, robocopy.exe). Once the files are successfully copied, they are executed remotely.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures the creation of command-line processes (cmd.exe, powershell.exe, xcopy.exe, robocopy.exe) and lists their full command arguments, allowing checks for network share formats.
  * NIDS (Suricata + Zeek): NO. While network monitoring can inspect SMB file transfer headers, decoding the command line of the process that initiated the transfer on the source system requires host-level auditing.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Lateral tool transfer can be detected using process creation and file event logs.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'file_path contains \C$\' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | the field 'file_path' is absent entirely; an absent field is no-match for every operator, so the stage is never entered |

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
