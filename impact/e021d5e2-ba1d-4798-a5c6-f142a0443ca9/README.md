# e021d5e2-ba1d-4798-a5c6-f142a0443ca9 — golden replay datasets

## Files

| File | Description |
|---|---|
| `rule.yml` | The detection rule(s) (Sigma & OCSF) |
| `benign_1.jsonl` | Benign telemetry |
| `true_positive_1.jsonl` | True positive telemetry |

## Replaying

Run the following script to execute the replay (this relies on the test execution engine):
```bash
$ python3 replay.py --datasets e021d5e2-ba1d-4798-a5c6-f142a0443ca9
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1491.002

* What it is: Defacement: External Defacement. Adversaries modify content or resources on external services (such as CDN endpoints, public DNS registries, or corporate landing pages hosted externally) to display messages, redirect traffic, or damage the organization's reputation.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688, and Sysmon File Creation/Modification events (Event ID 11).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Outbound deployment script arguments and local DNS server zone file writes are monitored.
  - NIDS (Suricata + Zeek): NO. Host-local deployment or zone modification execution.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

### 5. Test Cases (Engine Pipeline Verification)

#### True Positives
* True Positive 1A: Standard Execution (CDN or External Hosting Update Command Line (AN1622-A))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 1B: Malformed JSON Robustness Test (CDN or External Hosting Update Command Line (AN1622-A))
  * The Log: Simulating 1A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 1C: Schema Type Validation Failure (CDN or External Hosting Update Command Line (AN1622-A))
  * The Log: Exact match of 1A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 1D: Exact Duplicate Event (CDN or External Hosting Update Command Line (AN1622-A))
  * The Log: Exact duplicate of 1A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

* True Positive 2A: Standard Execution (Local DNS Server Zone File Modification (AN1622-B))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 2B: Malformed JSON Robustness Test (Local DNS Server Zone File Modification (AN1622-B))
  * The Log: Simulating 2A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 2C: Schema Type Validation Failure (Local DNS Server Zone File Modification (AN1622-B))
  * The Log: Exact match of 2A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 2D: Exact Duplicate Event (Local DNS Server Zone File Modification (AN1622-B))
  * The Log: Exact duplicate of 2A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

#### Benign / True Negatives
* Benign 1: Allowed Activity (CDN or External Hosting Update Command Line (AN1622-A))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

* Benign 2: Allowed Activity (Local DNS Server Zone File Modification (AN1622-B))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

### 6. Raw Telemetry Dataset (OCSF JSON)

#### Benign Telemetry
(See `benign_1.jsonl`)

#### True Positive Telemetry
(See `true_positive_1.jsonl`)
