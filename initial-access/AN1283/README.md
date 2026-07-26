# AN1283 — golden replay datasets

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
$ python3 replay.py --datasets AN1283
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1078.001

* What it is: Valid Accounts: Default Accounts. Operating systems and software packages are installed with default built-in accounts (e.g., Administrator, Guest in Windows). Adversaries scan for and exploit default accounts that have default passwords, weak passwords, or are left enabled. Operating systems with default accounts exposed to remote protocols like SMB or RDP represent primary targets.
* Log Source Requirements: Windows Security Event Log capturing authentication events, and network connection logs tracking access to default services.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Windows Security Event ID 4624 logs all successful authentication sessions. Sysmon Event ID 3 captures network connections.
  - NIDS (Suricata + Zeek): YES (Partial). Network security tools can identify authentication attempts over SMB or RDP.
* Log Sources Covered:
  - Security Event ID 4624 (security)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
