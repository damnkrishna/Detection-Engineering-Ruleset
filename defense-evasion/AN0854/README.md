# AN0854 — golden replay datasets

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
$ python3 replay.py --datasets AN0854
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1484.001

* What it is: Group Policy Modification. Adversaries modify Group Policy Objects (GPOs) to deploy malware, establish persistence, disable security settings, or escalate privileges across an Active Directory domain. By modifying GPO files within the domain's SYSVOL share, they can execute code on domain-joined systems.
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters from domain administrative utilities and scripting engines (like PowerShell, secedit.exe, or lgpo.exe).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs the execution of CLI tools like secedit.exe, lgpo.exe, or PowerShell containing GPO cmdlets.
  * NIDS (Suricata + Zeek): NO. GPO templates are loaded over SMB, but network logs cannot reliably inspect the contents of encrypted SMB traffic.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
