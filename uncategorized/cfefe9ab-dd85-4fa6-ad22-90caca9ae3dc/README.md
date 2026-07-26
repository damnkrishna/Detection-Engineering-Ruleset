# cfefe9ab-dd85-4fa6-ad22-90caca9ae3dc — golden replay datasets

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
$ python3 replay.py --datasets cfefe9ab-dd85-4fa6-ad22-90caca9ae3dc
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1484.002

* What it is: Domain or Tenant Policy Modification: Trust Modification. Adversaries modify Active Directory domain trust configurations to add new domain trusts or alter existing federations. This is often used for lateral movement or persistence, enabling trust from an attacker-controlled external domain.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) and Windows Security Event logs (Event ID 4662 - Active Directory Object Operation, or Event ID 5136 - Directory Service Object Modified).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Process logs capture the use of utility binaries (netdom, nltest, powershell) to query or modify trust.
  - NIDS (Suricata + Zeek): NO. Mapped protocol actions are local host operations.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
