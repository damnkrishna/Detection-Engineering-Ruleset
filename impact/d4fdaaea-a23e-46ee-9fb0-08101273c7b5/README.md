# d4fdaaea-a23e-46ee-9fb0-08101273c7b5 — golden replay datasets

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
$ python3 replay.py --datasets d4fdaaea-a23e-46ee-9fb0-08101273c7b5
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1496

* What it is: Resource Hijacking. Adversaries leverage compromised endpoint resources for unauthorized utility, typically for cryptomining (e.g. Monero mining). They deploy binaries or scripts that run persistently in the background, consuming CPU, GPU, and network resources.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) and Sysmon Network Connection events (Event ID 3).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Miner binaries and command lines are detected via process creation. Outbound pool network traffic is detected via network connections.
  - NIDS (Suricata + Zeek): YES. Stratum protocol signatures on outbound ports can be flagged by network IDS.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
