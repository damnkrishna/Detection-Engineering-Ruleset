# cbdf2001-a189-4db8-bb9a-7c9802cf0027 — golden replay datasets

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
$ python3 replay.py --datasets cbdf2001-a189-4db8-bb9a-7c9802cf0027
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1559.002

* What it is: Inter-Process Communication: Dynamic Data Exchange. Adversaries abuse the DDE protocol in Microsoft Office applications to execute shell commands or run malicious scripts without utilizing macro structures.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688, and Sysmon Registry Set events (Event ID 13).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. SCM child processes spawned by Office and registry edits enabling DDE execution are tracked.
  - NIDS (Suricata + Zeek): NO. Host-local application communication.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
