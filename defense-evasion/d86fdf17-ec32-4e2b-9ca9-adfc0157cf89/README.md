# d86fdf17-ec32-4e2b-9ca9-adfc0157cf89 — golden replay datasets

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
$ python3 replay.py --datasets d86fdf17-ec32-4e2b-9ca9-adfc0157cf89
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1564.011

* What it is: Ignore Process Interrupts. Adversaries configure scripts or processes to suppress error handling, ignore interrupt signals, and continue executing silently regardless of failures. On Windows, this is most commonly observed in PowerShell scripts using `-ErrorAction SilentlyContinue` or `$ErrorActionPreference = 'SilentlyContinue'`, which prevents error messages from appearing in console output or event logs. This technique allows adversaries to run reconnaissance or exploitation commands silently even when some steps fail, reducing detection likelihood from error-based monitoring.
* Log Source Requirements: PowerShell Script Block Logs (Event ID 4104), and Sysmon process creation logs (Event ID 1).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. PowerShell Script Block Logging (Event ID 4104) captures the content of PowerShell scripts including error suppression parameters. Sysmon Event ID 1 captures PowerShell and Cmd launches with error action suppression or redirection parameters.
    * NIDS (Suricata + Zeek): NO. Error suppression is a scripting-level construct.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
