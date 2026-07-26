# AN0616 — golden replay datasets

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
$ python3 replay.py --datasets AN0616
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1052.001

* What it is: Exfiltration Over Physical Medium: Exfiltration over USB. Adversaries exfiltrate data by writing files directly to USB mass storage devices. To accelerate data collection and minimize interactive steps, they often execute automated command-line copy tools (like robocopy.exe, xcopy.exe) or custom scripts to scan and copy targeted files directly to plugged-in USB drives. Detections monitor file writes onto removable drive paths by these copy utilities or the process execution command lines.
* Log Source Requirements: Endpoint logs capturing file creation events and process creation events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 11 (File Event) logs when copy utilities write files to USB drive paths, and Event ID 1 (Process Creation) logs copy command-line executions targeting removable storage.
* NIDS (Suricata + Zeek): NO. Offline, local host actions.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
