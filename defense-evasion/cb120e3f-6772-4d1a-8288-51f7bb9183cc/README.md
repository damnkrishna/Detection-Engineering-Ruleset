# cb120e3f-6772-4d1a-8288-51f7bb9183cc — golden replay datasets

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
$ python3 replay.py --datasets cb120e3f-6772-4d1a-8288-51f7bb9183cc
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1222.001

* What it is: File and Directory Permissions Modification: Windows Permissions. Adversaries modify Discretionary Access Control Lists (DACLs) and permissions using native Windows utilities (like `icacls.exe`, `takeown.exe`, `attrib.exe`) to access restricted files, hide malicious artifacts, or weaken system defenses.
* Log Source Requirements: Process creation logs (Sysmon Event ID 1 / Windows Security Event ID 4688) and Object Access logs (Windows Security Event ID 4670 - Permissions changed).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs the execution of utilities like `icacls.exe` and their command-line arguments.
    * NIDS (Suricata + Zeek): NO. File permissions manipulation is a local host filesystem activity.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
