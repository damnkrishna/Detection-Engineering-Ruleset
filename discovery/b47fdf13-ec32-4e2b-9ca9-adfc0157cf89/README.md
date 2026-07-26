# b47fdf13-ec32-4e2b-9ca9-adfc0157cf89 — golden replay datasets

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
$ python3 replay.py --datasets b47fdf13-ec32-4e2b-9ca9-adfc0157cf89
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1010

* What it is: Application Window Discovery. Adversaries may enumerate open windows to identify active applications, discover visible user activity, or determine the presence of monitoring tools on a compromised host. On Windows, tools use Win32 API calls like EnumWindows() or GetForegroundWindow() to list all top-level window handles and their associated titles. This information is used for situational awareness, screenshot targeting, or keylogger targeting.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) and PowerShell Script Block Logs (Event ID 4104).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 captures spawning of PowerShell or scripting hosts. Script Block logging captures the actual content of window enumeration cmdlets.
    * Windows Security Logs: PARTIAL. Security logs EID 4688 captures command lines if enabled.
* Log Sources Covered:
    - Sysmon Event ID 1 (process_creation)
    - PowerShell Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
    - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
