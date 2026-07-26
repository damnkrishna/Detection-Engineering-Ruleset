# AN0975 — golden replay datasets

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
$ python3 replay.py --datasets AN0975
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1548

* What it is: Abuse Elevation Control Mechanism. User Account Control (UAC) is a key Windows security feature that limits application privileges to standard user levels until an administrator authorizes an elevation. Adversaries bypass UAC by hijacking auto-elevated system binaries or hijacking COM objects and Registry paths to execute command payloads at High Integrity without triggering consent dialogs.
* Log Source Requirements: Endpoint logs capturing process creation events and registry modification events.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures parent process paths, target process paths, and command-line arguments. Sysmon Event ID 13 captures direct registry writes targeting bypass keys.
  - NIDS (Suricata + Zeek): NO. Elevation of privileges is entirely a local operating system event.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
