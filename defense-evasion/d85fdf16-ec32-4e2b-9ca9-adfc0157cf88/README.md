# d85fdf16-ec32-4e2b-9ca9-adfc0157cf88 — golden replay datasets

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
$ python3 replay.py --datasets d85fdf16-ec32-4e2b-9ca9-adfc0157cf88
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1564.012

* What it is: File/Path Exclusions. Adversaries exploit the fact that security tools (antivirus engines, EDR agents) maintain exclusion lists — directories, file paths, or extensions that are excluded from scanning or monitoring. By placing malicious files in excluded paths (e.g., `C:\Windows\Temp`, Exchange server directories, or custom AV exclusion paths set by admins), adversaries ensure their payloads are not scanned or detected. They may also actively add new exclusions using `powershell.exe Add-MpPreference` or registry modifications to create blind spots for their malware.
* Log Source Requirements: Sysmon process creation logs (Event ID 1), Windows Security Event ID 4688 (process creation), and Sysmon registry modification logs (Event ID 13) capturing Defender exclusions.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures PowerShell `Add-MpPreference -ExclusionPath` commands. Event ID 13 captures direct exclusion writes in the registry.
    * NIDS (Suricata + Zeek): NO. Exclusion list manipulation is a host-local operation.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
