# cd2aa272-d4b9-43a4-845a-eb378b273bcf — golden replay datasets

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
$ python3 replay.py --datasets cd2aa272-d4b9-43a4-845a-eb378b273bcf
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1690

* What it is: Prevent Command History Logging. Adversaries may disable the recording of command history in shells (like PowerShell or bash) to hide their execution artifacts. In Windows, this is commonly done by modifying the PSReadLine options in PowerShell, setting the `HistorySaveStyle` to `SaveNothing`, or pointing the `HistorySavePath` to `NUL` or a volatile location.
* Log Source Requirements: Process creation logs (Sysmon Event ID 1 / Windows Security Event ID 4688) and PowerShell Script Block Logging (Event ID 4104).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures command-line arguments. Event ID 4104 captures the script blocks executed inside the PowerShell session, even if history saving is disabled.
    * NIDS (Suricata + Zeek): NO. Command history manipulation is a local shell configuration activity.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
