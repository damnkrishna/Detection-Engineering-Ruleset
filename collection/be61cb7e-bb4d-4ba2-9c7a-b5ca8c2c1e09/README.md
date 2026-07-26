# be61cb7e-bb4d-4ba2-9c7a-b5ca8c2c1e09 — golden replay datasets

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
$ python3 replay.py --datasets be61cb7e-bb4d-4ba2-9c7a-b5ca8c2c1e09
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1119

* What it is: Automated Collection. Adversaries use scripts or utilities to automatically discover and collect files, clipboard content, or system information at scale. Rather than manually browsing and copying individual files, they run automated commands that recursively search for target file types (e.g., dir /s /b *.docx, Get-ChildItem -Recurse -Filter "*.pdf"), copy matching files to a staging location, and sometimes capture clipboard data in a loop. Detections monitor recursive CLI searches targeting sensitive document types, or automated staging drops of these files in temp folders.
* Log Source Requirements: Endpoint logs capturing process creation events and file creation events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs recursive command-line directory searches targeting document files, and Event ID 11 (File Event) logs bulk file creation/drops in temp staging folders.
* NIDS (Suricata + Zeek): NO. Offline, local host actions.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
