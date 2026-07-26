# cbdf2e03-a178-4db9-8b9a-7c9802cf6914 — golden replay datasets

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
$ python3 replay.py --datasets cbdf2e03-a178-4db9-8b9a-7c9802cf6914
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1059.010

* What it is: Command and Scripting Interpreter: AutoHotKey & AutoIT. Adversaries use compiled scripts or scripting interpreters like AutoHotKey and AutoIT to automate host operations, run obfuscated payloads, or evade standard shell-based script monitoring.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688, and Sysmon File Creation events (Event ID 11).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Interpreter execution and script file creation on local storage are monitored.
  - NIDS (Suricata + Zeek): NO. Host-local application scripting.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
