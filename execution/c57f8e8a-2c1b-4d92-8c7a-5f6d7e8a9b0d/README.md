# c57f8e8a-2c1b-4d92-8c7a-5f6d7e8a9b0d — golden replay datasets

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
$ python3 replay.py --datasets c57f8e8a-2c1b-4d92-8c7a-5f6d7e8a9b0d
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1574.005

* What it is: Hijack Execution Flow: Executable Installer File Permissions Weakness. Adversaries exploit weak directory permissions in software installation paths (such as subfolders in `%TEMP%` or custom application directories created by installers) to overwrite or replace legitimate binaries with their own malicious payloads. When the installer runs again under an elevated context (e.g., local admin or SYSTEM), it executes the replaced binary, resulting in privilege escalation.
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters (specifically targeting elevated process execution originating from temporary or user-writable directories).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs process executions, including the full resolved path of the executable (`Image`) and the token elevation level (`IntegrityLevel`).
* NIDS (Suricata + Zeek): NO. Exploiting local installer directory permission weaknesses is an endpoint-internal privilege escalation method. It generates no network logs.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
