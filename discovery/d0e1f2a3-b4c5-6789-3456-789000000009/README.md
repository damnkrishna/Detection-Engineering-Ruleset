# d0e1f2a3-b4c5-6789-3456-789000000009 — golden replay datasets

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
$ python3 replay.py --datasets d0e1f2a3-b4c5-6789-3456-789000000009
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1680

* What it is: Local Storage Discovery. Adversaries may enumerate local storage devices to identify data stores for collection or to locate credentials and sensitive files.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Process command lines are captured.
  - NIDS (Suricata + Zeek): NO. Host-local discovery.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
