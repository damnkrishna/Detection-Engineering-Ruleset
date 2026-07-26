# cd30d4a9-5e54-4e88-b46c-429201d9d4a4 — golden replay datasets

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
$ python3 replay.py --datasets cd30d4a9-5e54-4e88-b46c-429201d9d4a4
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1557.001

* What it is: Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay. Adversaries exploit local name resolution protocols (like LLMNR and NBT-NS) to intercept host lookup requests, respond with their own IP, and capture NTLM credential hashes. They can either crack these hashes offline or relay them to other network resources (SMB Relay) to gain unauthorized access.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) and Sysmon Network Connection events (Event ID 3).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Tool launches (e.g. Responder, Inveigh) and processes binding to UDP port 5355/137 or forwarding TCP 445 are visible.
  - NIDS (Suricata + Zeek): YES. Can detect anomalous LLMNR/NBT-NS responses returning non-existent host mappings.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
