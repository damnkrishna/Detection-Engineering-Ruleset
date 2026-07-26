# d47d228b-7ef5-41fc-9a4a-a5fff86b09f6 — golden replay datasets

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
$ python3 replay.py --datasets d47d228b-7ef5-41fc-9a4a-a5fff86b09f6
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1566.001

* What it is: Phishing: Spearphishing Attachment. Adversaries send emails containing malicious attachments (such as macro-enabled spreadsheets, script files, shortcuts, or disk images like `.iso` and `.img`) to establish a foothold. When the user opens the email or attempts to view the attachment, the email client (e.g., Outlook) writes the attachment file to the local disk (specifically to temporary download paths or temporary internet cache directories).
* Log Source Requirements: Sysmon File Creation logs (Event ID 11) and Sysmon process creation logs (Event ID 1).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 11 records the mail client process writing to disk. Sysmon Event ID 1 records the execution of processes directly from the mail attachment cache directory.
  * NIDS (Suricata + Zeek): YES. Network intrusion sensors analyze SMTP/IMAP streams and extract attachments, but endpoint-based process execution logs are necessary to verify execution.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
