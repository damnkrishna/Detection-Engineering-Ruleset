# dbaad872-9cc9-4177-ad6d-74d39f8f4a21 — golden replay datasets

## Files

| File | Description |
|---|---|
| `rule.yml` | The detection rule(s) (Sigma & OCSF) |
| `benign_1.jsonl` | Benign telemetry |
| `true_positive_1.jsonl` | True positive telemetry |

## Replaying

Run the following script to execute the replay (this relies on the test execution engine):
```bash
$ python3 replay.py --datasets dbaad872-9cc9-4177-ad6d-74d39f8f4a21
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1553

* What it is: Subvert Trust Controls. Adversaries may subvert trust controls to bypass security mechanisms that rely on digital certificates or code signing. This broad technique includes adding malicious root certificates to the trust store, modifying code signing policies, or installing unsigned drivers.
* Log Source Requirements: Process creation logs (Sysmon Event ID 1 / Windows Security Event ID 4688) and Registry modifications (Sysmon Event ID 13).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon can log the execution of certificate utilities like `certutil.exe` and registry changes to the Windows certificate stores (`Root`, `AuthRoot`).
    * NIDS (Suricata + Zeek): NO. Trust subversion is an endpoint configuration change.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

### 5. Test Cases (Engine Pipeline Verification)

#### True Positives
* True Positive 1A: Standard Execution (Subvert Trust Controls - Malicious Root Cert Install (AN1246))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 1B: Malformed JSON Robustness Test (Subvert Trust Controls - Malicious Root Cert Install (AN1246))
  * The Log: Simulating 1A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 1C: Schema Type Validation Failure (Subvert Trust Controls - Malicious Root Cert Install (AN1246))
  * The Log: Exact match of 1A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 1D: Exact Duplicate Event (Subvert Trust Controls - Malicious Root Cert Install (AN1246))
  * The Log: Exact duplicate of 1A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

#### Benign / True Negatives
* Benign 1: Allowed Activity (Subvert Trust Controls - Malicious Root Cert Install (AN1246))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

### 6. Raw Telemetry Dataset (OCSF JSON)

#### Benign Telemetry
(See `benign_1.jsonl`)

#### True Positive Telemetry
(See `true_positive_1.jsonl`)
