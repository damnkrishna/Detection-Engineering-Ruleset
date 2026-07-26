# AN0633 — golden replay datasets

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
$ python3 replay.py --datasets AN0633
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1571

* What it is: Non-Standard Port. Adversaries use non-standard ports to conduct C2 communications to bypass ingress/egress port filtering at firewall boundaries, evade signature-based detection systems, or tunnel commands. For instance, they may run HTTP traffic over port 4444 or 9001 instead of ports 80/443. Outbound connections or process configurations targeting high, non-standard destination ports represent primary indicators of compromise.
* Log Source Requirements: Endpoint logs capturing network connection details (Sysmon Event ID 3 / Windows Security Event ID 5156) and process creation logs (Sysmon Event ID 1).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 3 logs destination port metadata. Event ID 1 logs process creation command arguments.
    * Windows Security Logs: PARTIAL. Security logs EID 4688 captures command lines if enabled.
* Log Sources Covered:
    - Sysmon Event ID 3 (network_connection)
    - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
    - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
