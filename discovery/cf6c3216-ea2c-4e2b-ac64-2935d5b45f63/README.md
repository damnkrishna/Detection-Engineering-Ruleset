# cf6c3216-ea2c-4e2b-ac64-2935d5b45f63 — golden replay datasets

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
$ python3 replay.py --datasets cf6c3216-ea2c-4e2b-ac64-2935d5b45f63
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1057

* What it is: Process Discovery. Adversaries enumerate running processes on a target host to identify active security tools, running services, or user applications. The information helps adversaries determine if a host is being monitored, which security products are active, or where to inject malicious code. Common enumeration tools include tasklist.exe, wmic.exe process list, or PowerShell's Get-Process cmdlet.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) and PowerShell Script Block Logs (Event ID 4104).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 captures spawning of tasklist.exe, wmic.exe, and PowerShell. Event ID 4104 logs script block details.
    * Windows Security Logs: PARTIAL. Security logs EID 4688 captures command lines if enabled.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
