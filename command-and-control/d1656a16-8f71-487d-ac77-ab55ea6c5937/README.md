# d1656a16-8f71-487d-ac77-ab55ea6c5937 — golden replay datasets

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
$ python3 replay.py --datasets d1656a16-8f71-487d-ac77-ab55ea6c5937
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1105

* What it is: Ingress Tool Transfer. Adversaries transfer files (tools, exploits, payloads, or scripts) from external systems into a compromised corporate host. They abuse native Windows utilities (LOLBins) like certutil.exe, bitsadmin.exe, curl.exe, or scripting environments like PowerShell to connect to their external infrastructure and download malicious files onto the filesystem.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688), PowerShell Script Block Logs (Event ID 4104), and Network Connection logs (Sysmon Event ID 3).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 captures command lines. Event ID 4104 captures PowerShell scripts. Event ID 3 captures network activity.
    * Windows Security Logs: PARTIAL. Security logs EID 4688 captures command lines if enabled.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
