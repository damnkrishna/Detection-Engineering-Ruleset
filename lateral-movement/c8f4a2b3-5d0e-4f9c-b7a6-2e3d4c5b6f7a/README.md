# c8f4a2b3-5d0e-4f9c-b7a6-2e3d4c5b6f7a — golden replay datasets

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
$ python3 replay.py --datasets c8f4a2b3-5d0e-4f9c-b7a6-2e3d4c5b6f7a
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1021.005

* What it is: Remote Services: VNC. Adversaries install Virtual Network Computing (VNC) software on target systems to establish interactive GUI remote control sessions. This allows them to interact with the target machine directly, bypass standard administrative shell logs, and easily move laterally across the network. Detection focuses on identifying VNC server processes launching from non-standard folders or running as unauthorized services.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) and network connection logs (Event ID 3) capturing VNC client/server activity.
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 tracks VNC process execution, and Event ID 3 logs network connections targeting standard VNC ports.
  * Windows Security Logs: NO. Standard Windows Security Logs (service: security) do not capture active RFB protocol sessions or custom VNC software executions unless mapped specifically.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
