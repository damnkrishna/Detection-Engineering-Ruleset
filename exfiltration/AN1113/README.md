# AN1113 — golden replay datasets

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
$ python3 replay.py --datasets AN1113
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1020

* What it is: Automated Exfiltration. Adversaries automate the search, collection, packaging, and transmission of sensitive files using scheduled scripts or custom implants. Once deployed, these scripts execute at set intervals (using scheduled tasks or system daemons), compress targeted file formats (using LOLBins like tar.exe or makecab.exe), and transmit them to external infrastructure. Detections monitor automated archiving processes or the creation of staged compressed files in public directories.
* Log Source Requirements: Endpoint logs capturing process creation events and file creation events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs archiving command executions spawned by scheduling or scripting interpreters, and Event ID 11 (File Event) logs creation of staged archives.
* NIDS (Suricata + Zeek): YES (Partial). Outbound network logs can reveal periodic beaconing, but host logs are required to detect local staging.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
