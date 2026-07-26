# d374037f-ff05-4a12-a750-1345b1088275 — golden replay datasets

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
$ python3 replay.py --datasets d374037f-ff05-4a12-a750-1345b1088275
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1486

* What it is: Data Encrypted for Impact. Adversaries encrypt data on target systems to disrupt system availability and demand ransom. To perform this, they use native tools or custom malware to traverse the filesystem, modify extensions, write ransom notes, and disable recovery paths.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688, and Sysmon File Creation events (Event ID 11).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 11 logs file creation details. Sysmon Event ID 1 logs execution parameters.
  - NIDS (Suricata + Zeek): NO. Host-local filesystem modifications.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
