# 5e2e6baa-d6d5-4ea9-b545-3afcbca8667a — golden replay datasets

`Lateral Movement - WinRM Host Spawning Command Shell (AN1313)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1021.006

* What it is: Remote Services: Windows Remote Management. Adversaries abuse Windows Remote Management (WinRM), a native WS-Management protocol service, to execute commands remotely on hosts. When WinRM is leveraged (e.g., via Enter-PSSession or Invoke-Command), the WinRM service helper host wsmprovhost.exe is spawned on the target system to execute the user's command, often by spawning a child command interpreter shell (cmd.exe or powershell.exe). Monitoring this parent-child relationship helps identify remote PowerShell execution.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) auditing parent-child process setups.
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs the parent process of a newly spawned shell. If the parent is wsmprovhost.exe, it represents WinRM activity. Wazuh aggregates these events.
  * NIDS (Suricata + Zeek): YES. Network logs track WinRM HTTP/HTTPS connections (ports 5985, 5986), but host logs are needed to verify the specific commands launched.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - PowerShell Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Windows Remote Management executions can be detected using process creation and PowerShell script block logs.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'parent_image not_regex .*\Q\setup.exe\E$' — every other condition holds, so the stage gate rejects the events |
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
