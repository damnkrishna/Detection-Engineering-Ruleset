# be76dc5a-fbca-4c92-9118-a6d1bc89a74d — golden replay datasets

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
$ python3 replay.py --datasets be76dc5a-fbca-4c92-9118-a6d1bc89a74d
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1567.001

* What it is: Exfiltration Over Web Service: Exfiltration to Cloud Storage. Adversaries exfiltrate data by uploading files or source code directly to public, legitimate code repositories (such as GitHub, GitLab, or Bitbucket). They do this using CLI client tools (like git.exe or curl.exe) or scripting hosts (like PowerShell) to send HTTP POST requests directly to repository APIs. Because these repositories are trusted by IT departments, network connections to these domains are rarely blocked.
* Log Source Requirements: Endpoint logs capturing network connection events and process creation events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 3 (Network Connection) logs outbound network connections containing destination hostnames and initiating process names, and Event ID 1 (Process Creation) logs commands referencing repository domains.
* NIDS (Suricata + Zeek): YES. TLS handshake metadata and SNI hostnames reveal connections to public code repository domains.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
