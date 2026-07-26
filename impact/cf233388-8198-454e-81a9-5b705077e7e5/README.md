# cf233388-8198-454e-81a9-5b705077e7e5 — golden replay datasets

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
$ python3 replay.py --datasets cf233388-8198-454e-81a9-5b705077e7e5
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1499.001

* What it is: Endpoint Denial of Service: OS Exhaustion Flood. Adversaries exhaust system resources (such as kernel handles, threads, memory, or CPU) on target endpoints to crash the operating system or degrade it to an unusable state, locking out administrators and users.
* Log Source Requirements: Windows System Event Log (Event ID 2004 for Resource Exhaustion Diagnosis) and Sysmon Process Creation events (Event ID 1).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Host-level OS exhaustion diagnostics are natively captured by Windows Diagnostics-Performance log and System event log.
  - NIDS (Suricata + Zeek): NO. Host-local memory/kernel exhaustion.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
