# AN0643 — golden replay datasets

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
$ python3 replay.py --datasets AN0643
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1553.002

* What it is: Code Signing. Adversaries abuse code signing to bypass security controls (like Windows Defender Application Control/AppLocker) that filter unsigned or untrusted binaries. They accomplish this by signing malicious code with stolen certificates, purchasing certificates using fake identities, or generating self-signed certificates and installing them into the victim's trusted root store.
* Log Source Requirements: Endpoint logs capturing process creation or module loads with associated digital signature metadata (e.g., Sysmon Event ID 7 for Image Load or Event ID 1 for Process Creation).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 7 (Image Loaded) captures the file signature status (`Signed`, `Signature`, `SignatureStatus`) for loaded DLLs and EXEs. Wazuh can parse this to alert on revoked or invalid states.
* NIDS (Suricata + Zeek): NO. Code signing validation is an endpoint-local cryptographic process. Network tools cannot verify the validity or signature status of binaries in transit.
* Log Sources Covered:
  - Sysmon Event ID 13 (registry_set)
  - Sysmon Event ID 7 (image_load)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
