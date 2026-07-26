# d83fdf14-ec32-4d2b-9ca9-adfc0157cf86 — golden replay datasets

## Files

| File | Description |
|---|---|
| `rule.yml` | The detection rule(s) (Sigma & OCSF) |
| `expected.json` | The expected output of the rule |
| `proof.md` | The proof of the rule |
| `benign_1.jsonl` | Benign telemetry |
| `true_positive_1.jsonl` | True positive telemetry |

## Replaying

Run the following script to execute the replay (this relies on the test execution engine):
```bash
$ python3 replay.py --datasets d83fdf14-ec32-4d2b-9ca9-adfc0157cf86
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1070.009

* What it is: Clear Persistence. Adversaries remove artifacts they previously planted for persistence — such as scheduled tasks, registry run keys, services, or startup folder binaries — to cover their tracks and hinder forensic investigation after completing their objectives. On Windows, removal commands include `sc.exe delete <service>`, `schtasks.exe /delete /tn <task>`, `reg.exe delete <key>`, or PowerShell equivalents (`Remove-Item`, `Unregister-ScheduledTask`). The detection pattern focuses on deletion of known persistence mechanisms rather than creation.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688), Sysmon registry deletion logs (Event ID 12/13), and Windows Security Event ID 4699 (scheduled task deleted).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures `sc.exe delete`, `schtasks.exe /delete`, and `reg.exe delete` commands. Event ID 12/13 captures registry value/key deletions. Windows Security Event ID 4699 logs scheduled task deletion events.
    * NIDS (Suricata + Zeek): NO. Persistence artifact removal is a host-local operation.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
