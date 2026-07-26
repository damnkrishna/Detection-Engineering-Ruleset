# d2ccebb4-719a-4de0-9981-29ab8e0e108f — golden replay datasets

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
$ python3 replay.py --datasets d2ccebb4-719a-4de0-9981-29ab8e0e108f
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1529

* What it is: System Shutdown/Reboot. Adversaries shut down or reboot target systems to interrupt operations, cover their tracks, or initiate process updates (like loading altered boot records or driver payloads). They achieve this using built-in utilities (like `shutdown.exe`) or administration scripting engines.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688, and Windows System Event Log (Event ID 1074 indicating shutdown/restart initiator).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Invocations of shutdown commands are monitored. Windows System logs capture shutdown signals.
  - NIDS (Suricata + Zeek): NO. Host-local system state execution.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
