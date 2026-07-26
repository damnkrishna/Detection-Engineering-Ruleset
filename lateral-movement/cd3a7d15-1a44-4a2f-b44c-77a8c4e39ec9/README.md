# cd3a7d15-1a44-4a2f-b44c-77a8c4e39ec9 — golden replay datasets

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
$ python3 replay.py --datasets cd3a7d15-1a44-4a2f-b44c-77a8c4e39ec9
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1021.001

* What it is: Remote Services: Remote Desktop Protocol. Adversaries use Remote Desktop Protocol (RDP) to log in interactively to a remote system. Once they establish the RDP GUI session, they start executing administrative utilities or credential theft programs. Host-based detection checks for RDP sessions (Logon Type 10) running command shells, script hosts, or known discovery tools (like ipconfig.exe, net.exe) shortly after logon.
* Log Source Requirements: Windows Security Event Log Event ID 4624 (Logon) and Sysmon process creation logs (Event ID 1) linked by logon session ID.
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Windows Security logs capture Logon Type 10 (RDP) successful authentications. Sysmon logs process creation events containing the session's logon ID. Wazuh links these events.
  * NIDS (Suricata + Zeek): YES. Network filters detect outbound RDP sessions (port 3389) and track connection statistics, but cannot see what commands run inside the session.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - PowerShell Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Command execution in RDP sessions can be detected using process creation and PowerShell script block logs.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
