# d87fdf13-ec32-4e2b-9ca9-adfc0157cf88 — golden replay datasets

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
$ python3 replay.py --datasets d87fdf13-ec32-4e2b-9ca9-adfc0157cf88
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1217

* What it is: Browser Information Discovery. Adversaries access local browser artifact directories (such as Chrome, Edge, or Firefox profile folders) to enumerate bookmarks, browsing history, saved passwords, cookies, or autofill data. This information can reveal visited internal portals, credentials, or session tokens. On Windows, these artifacts are stored in user profile directories like `%LOCALAPPDATA%\Google\Chrome\User Data\`, `%APPDATA%\Mozilla\Firefox\Profiles\`, or `%LOCALAPPDATA%\Microsoft\Edge\User Data\`.
* Log Source Requirements: File event logs (Sysmon Event ID 11) and Process Creation logs (Sysmon Event ID 1) showing command-line access to browser profile directories.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 11 captures file-level operations. Event ID 1 logs CLI copy or query operations targeting these directories.
    * NIDS (Suricata + Zeek): NO. Local browser file access is host-local.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
