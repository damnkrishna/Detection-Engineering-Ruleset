# be164aca-e2f1-4c3a-9477-a828b61161b6 — golden replay datasets

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
$ python3 replay.py --datasets be164aca-e2f1-4c3a-9477-a828b61161b6
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1053

* What it is: Scheduled Task/Job. Adversaries register scheduled tasks or jobs to execute malicious code automatically on a system. This technique is commonly used for persistence (running code across system reboots), execution (spawning payloads), or privilege escalation (configuring tasks to run under the high-privilege `SYSTEM` context). On Windows, tasks are typically created using the native `schtasks.exe` utility, the legacy `at.exe` utility, or PowerShell Task Scheduler cmdlets.
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters (specifically targeting command line schedulers or script block logs).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs the invocation of tools like `schtasks.exe` or `at.exe`, and records command-line flags.
* NIDS (Suricata + Zeek): NO. Creating scheduled tasks is a host-local configuration action. It produces no direct network traffic.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
