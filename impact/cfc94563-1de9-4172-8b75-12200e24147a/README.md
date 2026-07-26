# cfc94563-1de9-4172-8b75-12200e24147a — golden replay datasets

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
$ python3 replay.py --datasets cfc94563-1de9-4172-8b75-12200e24147a
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1499.004

* What it is: Endpoint Denial of Service: Application or System Exploitation. Adversaries exploit application or OS-level vulnerabilities (e.g. CVE-based exploits) to crash or restart system services, causing immediate service denial. This is frequently used to disable local security agents or disrupt server application availability (like Exchange or SQL databases).
* Log Source Requirements: Windows System Event Log (Event ID 7031 / 7034 / 7036 for SCM) and Sysmon Process Creation events (Event ID 1).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. SCM crash details and exploit process chains are captured.
  - NIDS (Suricata + Zeek): YES. If the exploit occurs over the network, network IDS can flag exploit packet patterns.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
