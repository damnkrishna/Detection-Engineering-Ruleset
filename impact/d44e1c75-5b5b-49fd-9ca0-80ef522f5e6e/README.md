# d44e1c75-5b5b-49fd-9ca0-80ef522f5e6e — golden replay datasets

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
$ python3 replay.py --datasets d44e1c75-5b5b-49fd-9ca0-80ef522f5e6e
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1496.001

* What it is: Resource Hijacking: Compute Hijacking. Adversaries leverage compromised systems' computing power to mine cryptocurrency or run custom compute workloads. They achieve persistence by registering miners as system services or scheduling periodic mining tasks using built-in Windows utilities.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688, and Sysmon Registry Set events (Event ID 13).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Service creation in the registry and command-line task configurations are monitored.
  - NIDS (Suricata + Zeek): YES. Stratum protocol egress networks can be flagged by NIDS.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
