# cbdf2001-a189-4db8-bb9a-7c9802cf0025 — golden replay datasets

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
$ python3 replay.py --datasets cbdf2001-a189-4db8-bb9a-7c9802cf0025
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1559

* What it is: Inter-Process Communication. Adversaries abuse IPC mechanisms (like named pipes, COM objects, or DDE) to execute remote code, perform lateral movement, or bypass boundary defense configurations.
* Log Source Requirements: Sysmon Named Pipe Creation events (Event ID 17) and Sysmon Process Creation events (Event ID 1).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Named pipe creations and COM command execution registrations are tracked.
  - NIDS (Suricata + Zeek): NO. Host-local inter-process communication.
* Log Sources Covered:
  - Sysmon Event ID 17 (pipe_created)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
