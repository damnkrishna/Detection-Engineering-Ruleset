# c3d4e5f6-7a8b-9c0d-1e2f-3a4b5c6d7e80 — golden replay datasets

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
$ python3 replay.py --datasets c3d4e5f6-7a8b-9c0d-1e2f-3a4b5c6d7e80
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1006

* What it is: Direct Volume Access. Adversaries may bypass host-based file access controls and auditing mechanisms by directly accessing and reading/writing to the raw logical or physical disk volume. This is typically done to extract protected system files (like the SAM registry hive or NTDS.dit database) or to overwrite disk sectors.
* Log Source Requirements:
  * Sysmon Process Creation (Event ID 1) capturing process command-lines attempting to read raw device paths.
* Coverage Check:
  * HIDS (Sysmon): YES. Processes attempting direct volume access via CLI parameters leave traces.
  * NIDS (Zeek/Suricata): NO. Host-level raw disk access is entirely local.
* Log Sources Covered:
  * Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  * Standard Windows file system audit logs (since direct volume access bypasses standard NTFS file access audits).

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
