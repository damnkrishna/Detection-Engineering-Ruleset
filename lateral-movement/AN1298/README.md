# AN1298 — golden replay datasets

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
$ python3 replay.py --datasets AN1298
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1080

* What it is: Shared Content. Adversaries may deliver payloads to a system by tainting content that is shared across systems, e.g., in shared network directories or repositories. An administrative network share (such as C$, ADMIN$, or IPC$) is often used by lateral movement tools and adversaries to copy binaries, scripts, or shortcut files. Once dropped on the shared repository or administrative volume, these files can be executed by target hosts through remote scheduled tasks, remote service control, or manual user interaction.
* Log Source Requirements: Endpoint file creation events (e.g. Sysmon Event ID 11 / Windows Security Event ID 4663) monitoring writes to shared folders or administrative volumes.
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 11 logs the creation of files, their target paths, writing processes, and extensions.
  * NIDS (Suricata + Zeek): NO. While NIDS can track SMB file transfers, detecting file creation events on host volumes (like specific administrative shares mapped locally) requires host-based filesystem auditing.
* Log Sources Covered:
  - Sysmon Event ID 11 (file_event)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Dropping and executing tainted shared content can be detected using file event and process creation logs.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
