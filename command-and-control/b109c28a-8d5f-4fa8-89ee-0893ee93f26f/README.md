# b109c28a-8d5f-4fa8-89ee-0893ee93f26f — golden replay datasets

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
$ python3 replay.py --datasets b109c28a-8d5f-4fa8-89ee-0893ee93f26f
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1568

* What it is: Dynamic Resolution. Adversaries configure malware to generate C2 domain names dynamically using Domain Generation Algorithms (DGA). This bypasses static firewall blocks and IP domain blacklists because the malware queries a sequence of pseudo-random, high-entropy domains to find the active C2. DGA activity often manifests as system processes that typically perform no internet activity (e.g., calc.exe, notepad.exe) generating DNS queries or initiating network connections.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) and Network Connection logs (Sysmon Event ID 3).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 captures process creation. Event ID 3 logs outbound network connections.
    * Windows Security Logs: PARTIAL. Security logs EID 4688 captures command lines if enabled.
* Log Sources Covered:
    - Sysmon Event ID 3 (network_connection)
    - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
    - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
