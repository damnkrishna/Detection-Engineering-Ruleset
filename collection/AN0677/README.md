# AN0677 — golden replay datasets

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
$ python3 replay.py --datasets AN0677
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1213.006

* What it is: Databases. Adversaries target database systems to collect sensitive information stored in structured data stores — such as customer records, financial data, credentials, or intellectual property. On Windows, they use database client tools (sqlcmd.exe, isql.exe, osql.exe, bcp.exe, mysql.exe) to query databases and export results, often initiated from unexpected parent processes like cmd.exe, powershell.exe, or explorer.exe. The exported data is typically written to .csv, .sql, or .bak dump files in user temp directories.
* Log Source Requirements: Endpoint logs capturing process creation events and network connection events.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs database client tool execution. Sysmon Event ID 3 (Network Connection) logs database connection attempts.
  - NIDS (Suricata + Zeek): YES. Database connections to local or remote servers can be identified.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
