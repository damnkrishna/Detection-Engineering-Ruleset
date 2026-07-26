# d84fdf15-ec32-4e2b-9ca9-adfc0157cf87 — golden replay datasets

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
$ python3 replay.py --datasets d84fdf15-ec32-4e2b-9ca9-adfc0157cf87
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1218.012

* What it is: Verclsid. Adversaries abuse `verclsid.exe`, a signed Windows binary (part of the Windows Shell), to execute arbitrary COM objects by supplying a CLSID argument. Since `verclsid.exe` is a trusted, Microsoft-signed binary, security products often allow it to instantiate COM objects. Attackers register a malicious COM object (or point to a remote SCT/HTA scriptlet via an existing CLSID) and invoke it through `verclsid.exe /S /C {CLSID}`. If the CLSID resolves to remote content, `verclsid.exe` makes outbound network connections, loading and executing the remote scriptlet.
* Log Source Requirements: Sysmon process creation logs (Event ID 1), Sysmon network connection logs (Event ID 3), and Sysmon registry modification logs (Event ID 12/13) capturing custom CLSID creation.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures `verclsid.exe` process creation with CLSID arguments. Event ID 3 captures outbound network connections initiated by `verclsid.exe`. Event ID 12/13 detects custom CLSIDs written to user classes.
    * NIDS (Suricata + Zeek): PARTIAL. Outbound network traffic from verclsid.exe can be captured, but local host context is needed for correlation.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
