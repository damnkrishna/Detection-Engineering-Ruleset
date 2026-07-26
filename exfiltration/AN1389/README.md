# AN1389 — golden replay datasets

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
$ python3 replay.py --datasets AN1389
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1048.001

* What it is: Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol. Adversaries encrypt stolen files locally using symmetric cryptography (like AES-256) and upload the data via an alternative network protocol or a public file hosting API that is distinct from their primary C2 channel. Detections monitor scripting hosts loading cryptographic DLLs (bcryptprimitives.dll, cryptsp.dll) to prepare for secure transfers, or network connection events containing encryption-related commands.
* Log Source Requirements: Endpoint logs capturing image/library load events and network connection events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 7 (Image Load) logs when cryptographic DLLs are loaded by scripting engines, and Event ID 3 (Network Connection) logs outbound uploads initiated by these scripting processes.
* NIDS (Suricata + Zeek): YES (Partial). Outbound uploads over alternative channels are logged, but host-level context confirms local encryption actions.
* Log Sources Covered:
  - Sysmon Event ID 3 (network_connection)
  - Sysmon Event ID 7 (image_load)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
