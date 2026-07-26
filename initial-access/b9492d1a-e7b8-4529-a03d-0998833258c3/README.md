# b9492d1a-e7b8-4529-a03d-0998833258c3 — golden replay datasets

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
$ python3 replay.py --datasets b9492d1a-e7b8-4529-a03d-0998833258c3
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1669

* What it is: Wi-Fi Networks. Adversaries leverage rogue Wi-Fi access points (like Evil Twins) or connect corporate laptops to unauthorized, unencrypted public wireless networks to intercept traffic, perform man-in-the-middle (MitM) attacks, or bypass corporate egress filters. Detection involves monitoring processes executing wireless profile queries (e.g. netsh wlan show profiles).
* Log Source Requirements: Sysmon process creation logs (Event ID 1) and PowerShell script block logs (Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures network configuration queries (like netsh.exe wlan). Sysmon Event ID 4104 (Script Block) captures wireless profile queries executed via PowerShell commands.
  * Windows Security/Defender Logs: NO. These logs do not natively record Wi-Fi client association details unless specific verbose tracing is enabled in custom channels.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
