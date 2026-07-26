# d1d2e3f4-f5a6-4b7d-9e9f-0a1b2c3d4e5f — golden replay datasets

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
$ python3 replay.py --datasets d1d2e3f4-f5a6-4b7d-9e9f-0a1b2c3d4e5f
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1598

* What it is: Phishing for Information. Adversaries send phishing communications (typically emails) to target individuals to solicit sensitive organizational, credential, or system data. The email often links to a credential harvesting form or asks technical details from helpdesks.
* Log Source Requirements: Email server logs and gateway audits.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): NO. Handled by email server filters.
  - NIDS (Suricata + Zeek): NO. Focus is on email gateway and SMTP telemetry.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
