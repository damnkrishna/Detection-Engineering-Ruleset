# c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f — golden replay datasets

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
$ python3 replay.py --datasets c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1595
* What it is: Active Scanning. Adversaries scan the target organization's public networks to detect open ports, active services, vulnerabilities, and system details. This is an active probe that directly touches the boundary interfaces.
* Log Source Requirements: Firewall and Network IDS logs capturing connection metrics.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): NO. Local host logs do not capture boundary network probes.
  - NIDS (Suricata + Zeek): YES. Zeek dns/http/ssl and Suricata port scan alerts.
* Log Sources Covered:
  - Network IDS logs (Zeek/Suricata) (product: network, service: connection)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
