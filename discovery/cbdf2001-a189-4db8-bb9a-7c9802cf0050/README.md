# cbdf2001-a189-4db8-bb9a-7c9802cf0050 — golden replay datasets

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
$ python3 replay.py --datasets cbdf2001-a189-4db8-bb9a-7c9802cf0050
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1120

* What it is: Peripheral Device Discovery. Adversaries may attempt to gather information about attached peripheral devices (e.g., USB drives, cameras).
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688 / PowerShell Event ID 4104.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. PowerShell script block contents and process command lines are captured.
  - NIDS (Suricata + Zeek): NO. Host-local discovery.
* Log Sources Covered:
  - PowerShell Event ID 4104 (script_block)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
