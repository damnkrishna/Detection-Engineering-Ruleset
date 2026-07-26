# d4e5f6a7-b8c9-4d0e-9f0a-1b2c3d4e5f95 — golden replay datasets

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
$ python3 replay.py --datasets d4e5f6a7-b8c9-4d0e-9f0a-1b2c3d4e5f95
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1132

* What it is: Data Encoding. Adversaries may encode data (e.g., using Base64, Hexadecimal, or custom schemes) to obscure payload delivery or command and control traffic. This helps evade basic content filters or signature-based intrusion detection systems. Detecting the CLI execution of command parameters that invoke encoding functions (such as PowerShell base64/hex conversions) helps flag these obfuscation attempts.
* Log Source Requirements:
  * Sysmon Process Creation (Event ID 1) capturing process command-lines containing explicit data encoding/decoding keywords.
* Coverage Check:
  * HIDS (Sysmon): YES. Processes run with encoding/decoding arguments leave command-line logs.
  * NIDS (Zeek/Suricata): PARTIAL. Network logs can capture encoded payloads, but endpoint rules correlate the action to specific local processes.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
