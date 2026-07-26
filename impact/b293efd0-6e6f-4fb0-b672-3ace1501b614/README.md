# b293efd0-6e6f-4fb0-b672-3ace1501b614 — golden replay datasets

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
$ python3 replay.py --datasets b293efd0-6e6f-4fb0-b672-3ace1501b614
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1667

* What it is: Email Bombing. Adversaries send a high volume of emails to target addresses or use local relays to flood mail systems, aiming to exhaust mail queues, crash mail gateways, or distract security operations.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688, and Sysmon Network Connection events (Event ID 3).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Tool executions and network connection frequencies are tracked.
  - NIDS (Suricata + Zeek): YES. Mail flooding traffic can be flagged at the network boundary.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
