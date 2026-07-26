# c95af279-b364-4f47-9199-8016ebb95fb8 — golden replay datasets

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
$ python3 replay.py --datasets c95af279-b364-4f47-9199-8016ebb95fb8
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1499

* What it is: Endpoint Denial of Service. Adversaries target endpoints with resource exhaustion attacks or cause unexpected service terminations. The goal is to disable security controls, disrupt logging agents (like Sysmon, Wazuh, Defender), or crash business-critical server applications to prevent response or trigger outages.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Windows Security Event ID 4688, and Windows System Event Log (Event ID 7034).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Sysmon tracks stressing utilities; Windows System logs track service terminations.
  - NIDS (Suricata + Zeek): NO. Host-local resource and service states.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Windows System Log Event ID 7034 (service_terminated_unexpectedly)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
