# d1711116-0728-4f0f-9249-05cebecdca1b — golden replay datasets

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
$ python3 replay.py --datasets d1711116-0728-4f0f-9249-05cebecdca1b
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1003.002

* What it is: OS Credential Dumping: Security Account Manager (SAM). Adversaries target the SAM database on Windows to extract local account credentials (NTLM hashes). This allows them to crack passwords offline or use the hashes directly for pass-the-hash attacks. The most common method is exporting the SAM, SYSTEM, and SECURITY registry hives using built-in tools like reg.exe.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) tracking execution, registry write logs (Sysmon Event ID 13), and file system logs (Sysmon Event ID 11) tracking file creation.
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 (Process Creation) captures reg.exe execution. Event ID 13 (Registry Set) captures modification to registry hives. Event ID 11 (File Event) captures raw registry hive dumps written to disk.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
