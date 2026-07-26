# c7abc145-4d43-4735-ac76-ca50d56073fe — golden replay datasets

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
$ python3 replay.py --datasets c7abc145-4d43-4735-ac76-ca50d56073fe
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1565.001

* What it is: Stored Data Manipulation. Adversaries modify business-critical stored data (such as Office documents, PDF sheets, or text databases) to disrupt operations, alter business communications, or plant malicious macros/payloads. Under Windows, they use command-line shells or scripting engines to scan directories and modify file contents. Detections monitor local file modification events targeting document formats (.docx, .xlsx, .pdf) by execution shells, as well as command-line configurations referencing these extensions by scripting hosts.
* Log Source Requirements: Endpoint logs capturing file creation, modification, or write events (Sysmon Event ID 11 / Windows Security Event ID 4663) and process creation logs (Sysmon Event ID 1 / Windows Security Event ID 4688).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 11 logs file path names, extensions, and writing processes. Sysmon Event ID 1 captures command-line parameters containing document extensions executed by scripting interpreters.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 11 (file_event)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
