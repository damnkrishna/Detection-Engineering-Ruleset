# cbdf2001-a189-4db8-bb9a-7c9802cf0023 — golden replay datasets

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
$ python3 replay.py --datasets cbdf2001-a189-4db8-bb9a-7c9802cf0023
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1204

* What it is: User Execution. Adversaries rely on user actions (such as opening malicious email attachments, clicking malicious links, or launching zip/archive files) to initiate code execution.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Parent-child process relationships starting from user productivity software or archive managers are monitored.
  - NIDS (Suricata + Zeek): YES. Egress downloads or remote control connections initiated from user desktops can be analyzed.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
