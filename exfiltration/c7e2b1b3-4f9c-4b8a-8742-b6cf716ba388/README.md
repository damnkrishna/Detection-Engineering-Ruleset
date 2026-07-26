# c7e2b1b3-4f9c-4b8a-8742-b6cf716ba388 — golden replay datasets

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
$ python3 replay.py --datasets c7e2b1b3-4f9c-4b8a-8742-b6cf716ba388
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1052

* What it is: Exfiltration Over Physical Medium. Adversaries copy stolen data directly to removable media devices (such as USB flash drives, external hard drives, or writeable CDs/DVDs) to bypass network filters and perimeter controls. Detections monitor for files being written or created on removable storage drive letters (e.g., E:\, F:\) or command-line commands copying files to these drives.
* Log Source Requirements: Endpoint logs capturing file creation events and process creation events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 11 (File Event) logs archive file creation paths (including drive letters) and Sysmon Event ID 1 (Process Creation) logs CLI copy commands targeting removable storage.
* NIDS (Suricata + Zeek): NO. Physical media exfiltration is entirely local and offline.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
