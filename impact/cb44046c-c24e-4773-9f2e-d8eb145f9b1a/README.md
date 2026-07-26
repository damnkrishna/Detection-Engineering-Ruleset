# cb44046c-c24e-4773-9f2e-d8eb145f9b1a — golden replay datasets

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
$ python3 replay.py --datasets cb44046c-c24e-4773-9f2e-d8eb145f9b1a
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1498.001

* What it is: Network Denial of Service: Direct Network Flood. Adversaries generate a high volume of network traffic directly targeting a victim to saturate network interfaces, exhaust state tables, or crash endpoints. They achieve this using dedicated flooding tools (such as LOIC or HOIC) or custom scripts executing rapid connection loops.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688, and Sysmon Network Connection events (Event ID 3).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Flood binaries and process executions are tracked. Outbound connection rates are audited via Sysmon EID 3.
  - NIDS (Suricata + Zeek): YES. Network sensors are highly effective at detecting flood volumes at the network layer.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
