# cbdf2001-a189-4db8-bb9a-7c9802cf0029 — golden replay datasets

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
$ python3 replay.py --datasets cbdf2001-a189-4db8-bb9a-7c9802cf0029
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1059

* What it is: Command and Scripting Interpreter. Adversaries abuse default Windows script hosts like Windows Script Host (WSH - `wscript.exe` / `cscript.exe`) to execute malicious scripts (.vbs, .js) as part of their delivery or execution chain.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. WSH execution CLI parameters and parent processes are monitored.
  - NIDS (Suricata + Zeek): YES. Script-initiated network traffic can be tracked.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
