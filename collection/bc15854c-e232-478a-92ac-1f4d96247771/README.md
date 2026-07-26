# bc15854c-e232-478a-92ac-1f4d96247771 — golden replay datasets

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
$ python3 replay.py --datasets bc15854c-e232-478a-92ac-1f4d96247771
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1560.002

* What it is: Archive Collected Data: Archive via Library. Adversaries package collected data using compression library interfaces (such as `zlib`, `7-Zip` SDK, or `Ionic.Zip` for .NET) within their custom malware or scripts rather than executing standalone utilities. This allows them to compress files directly in memory or write them to disk without launching command shell utilities, bypassing simple process name filters. Detection focuses on identifying non-standard, unsigned applications loading compression runtime libraries (like `zlib1.dll`, `7z.dll`, `unrar.dll`, or `Ionic.Zip.dll`).
* Log Source Requirements: Sysmon Library Load logs (Event ID 7) and process creation logs (Event ID 1).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 7 records process image loads, allowing security tools to detect when an application in a user temp directory loads a compression DLL.
    * NIDS (Suricata + Zeek): NO. Network devices cannot audit system dynamic link library loads on physical host systems.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
