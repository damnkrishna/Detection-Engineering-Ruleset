# AN0781 — golden replay datasets

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
$ python3 replay.py --datasets AN0781
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1112

* What it is: Modify Registry. This involves adversaries modifying the Windows registry to achieve persistence, privilege escalation, or defense evasion. Specifically, targeting critical system settings like `Winlogon\Notify`, `Winlogon\Userinit`, and startup keys (`Run`, `RunOnce`) allows malicious binaries to load automatically on logon or boot. Disabling security settings like `SafeDllSearchMode` (forcing it to search the current working directory first) enables DLL hijacking attacks.
* Log Source Requirements: Telemetry focusing on process creation and command-line execution (specifically Windows CLI registry modification tools).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) captures execution of `reg.exe`, `powershell.exe`, or `wmic.exe` with command-line arguments targeting these keys. Wazuh scans these events to flag malicious registry commands.
* NIDS (Suricata + Zeek): NO. Registry modifications are local host-level configuration changes. They do not generate direct network traffic, making NIDS blind to the modification itself (though network telemetry might catch follow-on C2 traffic or the initial download of payloads).
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
