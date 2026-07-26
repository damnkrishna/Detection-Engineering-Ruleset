# d4e2f1a3-6b8c-4d9e-a7f2-3c1b2a4d5e6f — golden replay datasets

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
$ python3 replay.py --datasets d4e2f1a3-6b8c-4d9e-a7f2-3c1b2a4d5e6f
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1563

* What it is: Remote Service Session Hijacking. Adversaries may hijack an existing session of a remote service (such as RDP or ssh) to move laterally and bypass multi-factor authentication or credentials requirements. On Windows, RDP session shadowing (mstsc.exe /shadow) or session redirection (tscon.exe) allows administrators or attackers to hijack or observe user sessions. Before hijacking, adversaries typically run query utilities (like query.exe user or qwinsta.exe) to list active terminal sessions and discover session IDs.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs process paths (mstsc.exe, tscon.exe, query.exe, qwinsta.exe) and command line parameters.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
