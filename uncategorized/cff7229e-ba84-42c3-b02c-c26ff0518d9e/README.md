# cff7229e-ba84-42c3-b02c-c26ff0518d9e — golden replay datasets

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
$ python3 replay.py --datasets cff7229e-ba84-42c3-b02c-c26ff0518d9e
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1556.001

* What it is: Modify Authentication Process: Domain Controller Authentication. Adversaries patch domain controller authentication processes (specifically LSASS) to inject a "Skeleton Key," allowing them to authenticate as any user using a master password while legitimate authentication processes continue working normally.
* Log Source Requirements: Sysmon Process Access logs (Event ID 10), Sysmon Image Load logs (Event ID 7), and Sysmon Registry Set logs (Event ID 13).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Sysmon provides visibility into LSASS memory access, image loads, and registry changes on Domain Controllers.
  - NIDS (Suricata + Zeek): NO. Host-local system manipulation.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
