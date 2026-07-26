# AN1118 — golden replay datasets

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
$ python3 replay.py --datasets AN1118
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1029

* What it is: Scheduled Transfer. Adversaries schedule data exfiltration to align with normal business hours or system maintenance windows, making their transfers less noticeable. This is typically implemented via Windows Scheduled Tasks executing script blocks or command utilities (such as curl.exe, powershell.exe) that initiate file transfers to remote destinations. Detections monitor scheduled processes executing transfer cmdlets/arguments, or scheduled task XML files written to the Tasks directory.
* Log Source Requirements: Endpoint logs capturing process creation events and file creation events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs process spawning by the Task Scheduler engine with transfer arguments, and Event ID 11 (File Event) logs task definition XML file writes under System32\Tasks.
* NIDS (Suricata + Zeek): YES (Partial). Outbound network traffic can indicate periodic beaconing.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
