# cdef9001-a189-4db8-bb9a-7c9802cf0040 — golden replay datasets

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
$ python3 replay.py --datasets cdef9001-a189-4db8-bb9a-7c9802cf0040
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1007

* What it is: System Service Discovery. Adversaries may try to get information about registered local system services.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Process command lines are captured.
  - NIDS (Suricata + Zeek): NO. Host-local discovery.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
