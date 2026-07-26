# AN0954 — golden replay datasets

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
$ python3 replay.py --datasets AN0954
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1550

* What it is: Use Alternate Authentication Material. Adversaries may use alternate authentication material, such as password hashes (Pass-the-Hash), Kerberos tickets (Pass-the-Ticket), or access tokens, to authenticate to a system and move laterally without knowing the plaintext password. On Windows systems, tools like Mimikatz or Rubeus generate a Logon Type 9 (NewCredentials) session when credentials are cloned or impersonated for outbound network usage (e.g. runas /netonly or ticket injection).
* Log Source Requirements: Windows Security Event Log ID 4624 (Successful Logon) which records the Logon Type and authentication mechanism.
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Wazuh collects Windows Security Event ID 4624, which contains the logon type, source IP address, target user account, and process name.
  * NIDS (Suricata + Zeek): NO. Alternate authentication using local session cloning or ticket cache injection occurs host-locally before outbound network requests are made. While NIDS can flag anomalies in Kerberos traffic (e.g. unusual encryption types), it cannot directly observe logon session creation details.
* Log Sources Covered:
  - Windows Security Log Event ID 4624 (security)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Use of alternate authentication material can be detected using logon logs and process creation logs.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
