# cfcab073-866d-427e-be8a-2923bfad0a9c — golden replay datasets

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
$ python3 replay.py --datasets cfcab073-866d-427e-be8a-2923bfad0a9c
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1546.001

* What it is: Event Triggered Execution: Change Default File Association. When a user double-clicks or opens a file, the Windows operating system executes the default application associated with that file extension (e.g., Notepad for .txt files). Adversaries modify these default associations (stored under HKLM\SOFTWARE\Classes or HKCU\Software\Classes) using utilities like assoc.exe or ftype.exe. This causes a malicious binary to run whenever a specific, commonly-opened file type is loaded.
* Log Source Requirements: Endpoint logs capturing process creation events and registry modifications.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs process execution of assoc.exe/ftype.exe and registry commands. Sysmon Event ID 13 captures direct registry writes.
  - NIDS (Suricata + Zeek): NO. Local configuration change.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
