# AN1094 — golden replay datasets

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
$ python3 replay.py --datasets AN1094
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1548.002

* What it is: Bypass User Account Control. Windows User Account Control (UAC) allows a program to run with administrative privileges if approved by the user. Adversaries bypass this mechanism by exploiting auto-elevating programs that run with High Integrity without prompting. They do this by modifying registry entries (e.g., isolatedCommand, DelegateExecute, or shell\open\command keys) under the current user hive (HKCU), causing the auto-elevating binary to load a custom command instead of the default.
* Log Source Requirements: Endpoint logs capturing process creation events and registry modifications.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures command line arguments for tools modifying registry keys. Sysmon Event ID 13 (Registry Value Set) tracks direct registry modifications.
  - NIDS (Suricata + Zeek): NO. Registry modifications are internal Windows operating system events.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
