# c3d4e5f6-7a8b-9c0d-1e2f-3a4b5c6d7e95 — golden replay datasets

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
$ python3 replay.py --datasets c3d4e5f6-7a8b-9c0d-1e2f-3a4b5c6d7e95
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1211

* What it is: Exploitation for Stealth. Adversaries may exploit software vulnerabilities to bypass security tools, disable auditing, or hide their presence on target systems. A common technique involves process hollowing or process injection into trusted OS processes. This is detected by monitoring anomalous memory access requests (specifically write and mapping access rights) targeting critical system processes.
* Log Source Requirements:
  * Sysmon Process Access (Event ID 10) capturing handle requests to system processes with high-privilege access rights.
* Coverage Check:
  * HIDS (Sysmon): YES. Handle openings to critical processes with write or operation rights generate Event ID 10.
  * NIDS (Zeek/Suricata): NO. Process memory access is local to the operating system kernel.
* Log Sources Covered:
  * Sysmon Event ID 10 (process_access)
* Log Sources Missing / Unused:
  * None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
