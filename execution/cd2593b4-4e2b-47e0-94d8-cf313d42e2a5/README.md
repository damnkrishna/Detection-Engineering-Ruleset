# cd2593b4-4e2b-47e0-94d8-cf313d42e2a5 — golden replay datasets

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
$ python3 replay.py --datasets cd2593b4-4e2b-47e0-94d8-cf313d42e2a5
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1559.001

* What it is: Inter-Process Communication: Component Object Model. Adversaries use the Windows Component Object Model (COM) for code execution and persistence. They can interact with COM objects locally or remotely (DCOM) to spawn processes (e.g., using `MMC20.Application` or `ShellWindows`), bypassing typical parent-child process relationships and often evading standard command-line logging.
* Log Source Requirements: Process creation logs (Sysmon Event ID 1), Registry modification logs (Sysmon Event ID 12/13/14), and Network connection logs for DCOM (Sysmon Event ID 3).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures unusual processes spawned by `svchost.exe -k DcomLaunch` or `dllhost.exe`. Registry logs capture COM hijacking.
    * NIDS (Suricata + Zeek): PARTIAL. Network sensors can identify Distributed COM (DCOM) traffic (RPC/TCP 135 and dynamic ports) indicating remote execution attempts.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
