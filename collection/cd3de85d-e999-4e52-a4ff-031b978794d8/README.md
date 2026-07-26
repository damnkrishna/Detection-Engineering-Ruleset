# cd3de85d-e999-4e52-a4ff-031b978794d8 — golden replay datasets

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
$ python3 replay.py --datasets cd3de85d-e999-4e52-a4ff-031b978794d8
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1056.001

* What it is: Input Capture: Keylogging. Adversaries use keylogging software or APIs to record user keystrokes, aiming to harvest passwords, credentials, and sensitive inputs. Once installed, these tools run in the background, writing logs locally or beaconing them out.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) and Sysmon Registry Set events (Event ID 13).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Sysmon provides visibility into process creations, command-line execution, and registry modifications.
  - NIDS (Suricata + Zeek): NO. Host-local capture mechanism.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
