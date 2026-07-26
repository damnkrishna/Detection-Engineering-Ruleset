# c8b7c4d5-1a2b-3c4d-5e6f-7a8b9c0d1e2f — golden replay datasets

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
$ python3 replay.py --datasets c8b7c4d5-1a2b-3c4d-5e6f-7a8b9c0d1e2f
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1068

* What it is: Exploitation for Privilege Escalation. Adversaries may exploit software vulnerabilities in the operating system kernel or locally installed applications to execute code with higher privileges (e.g., moving from a standard user to `SYSTEM` or `root`). This often involves exploiting kernel drivers (e.g., Capcom.sys, vulnerable print spooler drivers).
* Log Source Requirements: Process creation logs (Sysmon Event ID 1), Windows Application Crash logs, and Driver Load events (Sysmon Event ID 6).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon tracks driver loads (Event ID 6) and process creations indicating a sudden shift to `SYSTEM` context.
    * NIDS (Suricata + Zeek): NO. Local kernel exploitation is entirely host-bound.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
