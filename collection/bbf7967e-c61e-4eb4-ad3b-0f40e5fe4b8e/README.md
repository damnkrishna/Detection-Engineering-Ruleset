# bbf7967e-c61e-4eb4-ad3b-0f40e5fe4b8e — golden replay datasets

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
$ python3 replay.py --datasets bbf7967e-c61e-4eb4-ad3b-0f40e5fe4b8e
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1056.003

* What it is: Input Capture: Web Portal Capture. Adversaries modify or deploy malicious login pages on legitimate web servers (e.g., IIS, Apache, Tomcat) to harvest user credentials. When users attempt to log in, the modified portal captures and logs their usernames and passwords in cleartext before passing them to the actual authentication service.
* Log Source Requirements: Sysmon File Creation events (Event ID 11).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. File write activity inside web server root folders is audited natively.
  - NIDS (Suricata + Zeek): NO. Mapped protocols are host-local filesystem changes.
* Log Sources Covered:
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
