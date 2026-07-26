# bc47b72b-b56a-487a-aaa0-8e1e1bf703bf — golden replay datasets

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
$ python3 replay.py --datasets bc47b72b-b56a-487a-aaa0-8e1e1bf703bf
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1210

* What it is: Exploitation of Remote Services. Adversaries exploit security vulnerabilities (such as buffer overflows or remote code execution bugs) in network services (like Print Spooler spoolsv.exe, Local Security Authority Subsystem lsass.exe, RPC service host svchost.exe, or SMB helper service) to run commands or shellcode. Successful exploitation typically results in these high-privilege system services spawning command interpreters (cmd.exe, powershell.exe) or staging binaries, which is an extremely anomalous execution pattern.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) capturing parent-child process chains and account context.
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures parent process paths (e.g., spoolsv.exe, lsass.exe) launching child programs. Wazuh aggregates these and triggers immediate high-severity warnings.
  * NIDS (Suricata + Zeek): YES. Network logs track exploit attempts (like RPC or SMB exploitation payloads) on boundary interfaces, but host logs are needed to verify if shell execution followed.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - PowerShell Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
