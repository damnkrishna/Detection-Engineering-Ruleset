# AN1137 — golden replay datasets

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
$ python3 replay.py --datasets AN1137
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1078.003

* What it is: Valid Accounts: Local Accounts. Local accounts exist on individual systems and are managed locally (e.g., the built-in local Administrator account). Adversaries exploit local accounts to move laterally between endpoints (using Logon Type 3 network connections) by leveraging credential reuse (where multiple workstations share the same local administrator password). Monitoring successful network logons using local administrative accounts is a highly effective method to identify lateral movement.
* Log Source Requirements: Windows Security Event Log capturing authentication events, and network connection logs tracking access to remote systems.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Windows Security Event ID 4624 logs network logon sessions. Sysmon Event ID 3 captures network connection details.
  - NIDS (Suricata + Zeek): YES (Partial). Network security tools can identify authentication attempts over SMB.
* Log Sources Covered:
  - Security Event ID 4624 (security)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
