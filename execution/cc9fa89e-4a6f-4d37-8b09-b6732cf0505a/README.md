# cc9fa89e-4a6f-4d37-8b09-b6732cf0505a — golden replay datasets

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
$ python3 replay.py --datasets cc9fa89e-4a6f-4d37-8b09-b6732cf0505a
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1204.002

* What it is: User Execution: Malicious File. Adversaries rely on a user opening a malicious file (e.g., an Office document, PDF, script, or executable) delivered via email, USB, or download. When opened, the file exploits a vulnerability, runs macros, or directly executes malicious code. This typically manifests as a user-facing application (Word, archiver) dropping payloads into user-controlled paths and spawning script engines.
* Log Source Requirements: Process creation logs (Sysmon Event ID 1) and File Creation logs (Sysmon Event ID 11).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon tracks the execution chain (e.g., WinRAR spawning a `.bat` file) and files dropped into `Downloads` or `Temp`.
    * NIDS (Suricata + Zeek): PARTIAL. NIDS can detect the malicious file being downloaded (e.g., analyzing an unencrypted email attachment or HTTP download), but not the local execution.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
