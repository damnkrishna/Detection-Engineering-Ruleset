# d886baae-081e-4ca1-aa0a-d5ab6d019b5d — golden replay datasets

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
$ python3 replay.py --datasets d886baae-081e-4ca1-aa0a-d5ab6d019b5d
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1499.003

* What it is: Endpoint Denial of Service: Application Exhaustion Flood. Adversaries target application services (such as web servers, database endpoints, or custom enterprise APIs) with high-rate connection requests to consume execution threads, socket tables, or CPU.
* Log Source Requirements: Sysmon Network Connection events (Event ID 3) / Web Server Logs.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. High volume connections to local listening application ports can be captured by local endpoint network logs.
  - NIDS (Suricata + Zeek): YES. Rapid connection attempts targeting application ports are highly visible on network interfaces.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
