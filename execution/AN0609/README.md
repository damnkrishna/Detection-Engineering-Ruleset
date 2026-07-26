# AN0609 — golden replay datasets

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
$ python3 replay.py --datasets AN0609
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1574

* What it is: Hijack Execution Flow. Adversaries modify the environment Windows uses to locate and execute programs (such as DLL load paths, service binary configurations, or application pathways) to hijack execution flow. By changing the binPath of a service, pointing a service's ServiceDll registry key to a malicious module, or modifying Image File Execution Options (IFEO) registry keys, they force system processes or applications to run their payload.
* Log Source Requirements: Endpoint logs capturing process creation and registry modifications.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs configuration utilities like sc.exe and reg.exe, and Event ID 13 (Registry Set) logs direct service path or IFEO debugger registry writes.
* NIDS (Suricata + Zeek): NO. Local host configurations.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
