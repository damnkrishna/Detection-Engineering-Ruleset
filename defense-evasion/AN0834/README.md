# AN0834 — golden replay datasets

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
$ python3 replay.py --datasets AN0834
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1222

* What it is: File and Directory Permissions Modification. Adversaries modify file and directory permissions (DACLs) and attributes to bypass access controls, escalate privileges, or evade detection. They use built-in Windows utilities like `icacls`, `cacls`, `takeown`, and `attrib` to grant themselves full control over system directories, deny access to defenders/security tools, remove audit trails, or hide malicious binaries under system and hidden attributes.
* Log Source Requirements: Endpoint logs capturing process creation and command-line execution (specifically Windows CLI utilities modifying DACLs or attributes).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) captures when utilities like `icacls.exe`, `cacls.exe`, `takeown.exe`, or `attrib.exe` are spawned, including their command-line arguments.
* NIDS (Suricata + Zeek): NO. DACL and attribute modifications are local system/operating system tasks. They generate no network traffic.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
