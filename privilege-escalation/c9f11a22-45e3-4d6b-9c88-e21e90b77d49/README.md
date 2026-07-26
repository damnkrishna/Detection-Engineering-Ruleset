# c9f11a22-45e3-4d6b-9c88-e21e90b77d49 — golden replay datasets

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
$ python3 replay.py --datasets c9f11a22-45e3-4d6b-9c88-e21e90b77d49
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1134.005

* What it is: Access Token Manipulation: SID-History Injection. The `sIDHistory` attribute in Active Directory is used during migrations to preserve access rights from an old domain to a new one. Adversaries can inject SIDs of highly privileged groups (like Enterprise Admins or Domain Admins) into the `sIDHistory` attribute of a standard user account. When this standard user logs in, they receive the permissions of the injected SIDs, effectively granting them domain administrator access while appearing as a normal user.
* Log Source Requirements: Windows Security Event Log (Event ID 4742 - Computer account changed, Event ID 4738 - User account changed, Event ID 4769 - Kerberos service ticket requested).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Windows Security logs on the Domain Controller capture modifications to user and computer accounts, including the `sIDHistory` attribute.
    * NIDS (Suricata + Zeek): NO. While LDAP and Kerberos traffic occurs, the specific manipulation of the SID is best caught at the AD audit log level.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
