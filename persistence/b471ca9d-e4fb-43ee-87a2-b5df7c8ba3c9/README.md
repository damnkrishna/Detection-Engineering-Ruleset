# b471ca9d-e4fb-43ee-87a2-b5df7c8ba3c9 — golden replay datasets

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
$ python3 replay.py --datasets b471ca9d-e4fb-43ee-87a2-b5df7c8ba3c9
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1136.002

* What it is: Domain Account Creation. Adversaries create new domain user accounts to establish persistent access to compromised environments. Unlike local accounts, domain accounts provide access across all domain-joined systems. On Windows, this is typically performed via net.exe user /add /domain, PowerShell Active Directory cmdlets (New-ADUser), or LDAP writes to Active Directory.
* Log Source Requirements: Endpoint logs capturing process creation events and system events (specifically Windows Security Log Event ID 4720).
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures net.exe and PowerShell AD cmdlets. Windows Security Event ID 4720 captures user account creation on Domain Controllers.
  - NIDS (Suricata + Zeek): NO. Focuses on local AD log sources.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Security Event ID 4720 (security)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
