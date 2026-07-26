# AN0787 — golden replay datasets

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
$ python3 replay.py --datasets AN0787
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1567.003

* What it is: Exfiltration Over Web Service: Exfiltration to Code Repository. Adversaries exfiltrate sensitive files or credentials by uploading their content as plain text snippets to public paste bins (such as Pastebin, Hastebin, or Ghostbin) where text can be hosted anonymously. Detections target processes initiating connections over domains associated with these sites, or CLI command-line parameters specifying paste bin destinations.
* Log Source Requirements: Endpoint logs capturing network connection events and process creation events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 3 (Network Connection) logs outbound connections targeting public paste site domains, and Event ID 1 (Process Creation) logs commands referencing these domains.
* NIDS (Suricata + Zeek): YES. Network boundary logs capture TLS handshake metadata and SNI hostnames for paste bin sites.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
