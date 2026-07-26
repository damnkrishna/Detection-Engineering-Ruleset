# d4e5f6a7-b8c9-4d0e-9f0a-1b2c3d4e5f80 — golden replay datasets

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
$ python3 replay.py --datasets d4e5f6a7-b8c9-4d0e-9f0a-1b2c3d4e5f80
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1008

* What it is: Fallback Channels. Adversaries may deploy secondary or redundant command and control (C2) channels to preserve system access in the event that primary communication pathways are discovered and severed by defender response actions. This commonly involves running local proxy or network tunneling daemons that tunnel traffic through alternative ports or protocols (e.g., Tor or proxy-over-DNS).
* Log Source Requirements:
  * Sysmon Process Creation (Event ID 1) to audit C2 proxy binaries and socks tunnel wrappers.
* Coverage Check:
  * HIDS (Sysmon): YES. Spawning fallback tools or proxies triggers process creation logging.
  * NIDS (Zeek/Suricata): PARTIAL. Network tools capture Tor handshake packets or DNS tunneling, but endpoint rules provide context on which local process initiated the channel.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
