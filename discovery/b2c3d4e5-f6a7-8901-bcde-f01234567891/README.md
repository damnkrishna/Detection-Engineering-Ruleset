# b2c3d4e5-f6a7-8901-bcde-f01234567891 — golden replay datasets

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
$ python3 replay.py --datasets b2c3d4e5-f6a7-8901-bcde-f01234567891
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1614

* What it is: System Location Discovery. Adversaries may gather information in an attempt to calculate the geographical location of a victim in order to infer their operational environment.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688 / PowerShell Event ID 4104.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. PowerShell and reg.exe command lines are captured.
  - NIDS (Suricata + Zeek): NO. Host-local discovery.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
