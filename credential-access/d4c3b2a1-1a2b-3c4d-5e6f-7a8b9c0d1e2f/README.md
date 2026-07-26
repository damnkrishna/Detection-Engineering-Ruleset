# d4c3b2a1-1a2b-3c4d-5e6f-7a8b9c0d1e2f — golden replay datasets

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
$ python3 replay.py --datasets d4c3b2a1-1a2b-3c4d-5e6f-7a8b9c0d1e2f
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1558.001

* What it is: Steal or Forge Kerberos Tickets: Golden Ticket. If an adversary compromises your Domain Controller and extracts the KRBTGT account password hash, they can use it to cryptographically forge their own Kerberos Ticket-Granting Tickets (TGTs). This "Golden Ticket" grants them unfettered, persistent administrative access to virtually any resource in the Active Directory domain, even if the user account they are impersonating has its password changed.
* Log Source Requirements: Detecting the creation of the ticket requires endpoint process/command-line monitoring (Sysmon Event ID 1) and PowerShell script block logging (Sysmon Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 (Process Creation) can detect the command-line execution of popular forging tools like Mimikatz or Rubeus on compromised endpoints. Sysmon Event ID 4104 (Script Block) is effective at catching script-based forging.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
