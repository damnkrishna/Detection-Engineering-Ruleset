# db194318-fb23-42ec-b891-ad5a8c835cb9 — golden replay datasets

## Files

| File | Description |
|---|---|
| `rule.yml` | The detection rule(s) (Sigma & OCSF) |
| `benign_1.jsonl` | Benign telemetry |
| `true_positive_1.jsonl` | True positive telemetry |

## Replaying

Run the following script to execute the replay (this relies on the test execution engine):
```bash
$ python3 replay.py --datasets db194318-fb23-42ec-b891-ad5a8c835cb9
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1547.012

* What it is: Boot or Logon Autostart Execution: Print Processors. The Windows print spooler service (spoolsv.exe) loads printer drivers and print processors during system startup or printer service initialization. Print processors are DLLs responsible for converting print job data into printer-ready formats. Adversaries can achieve privilege escalation and persistence by installing a malicious DLL as a custom print processor. They register it under the registry path HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\<CustomProcessor>\.
* Log Source Requirements: Endpoint logs capturing process creation events and registry modification events.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs CLI command lines modifying spooler registry paths. Sysmon Event ID 13 captures direct registry writes under Print Processor keys.
  - NIDS (Suricata + Zeek): NO. Host-level printer subsystem activity.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

### 5. Test Cases (Engine Pipeline Verification)

#### True Positives
* True Positive 1A: Standard Execution (Custom Print Processor Installation via CLI (AN0074))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 1B: Malformed JSON Robustness Test (Custom Print Processor Installation via CLI (AN0074))
  * The Log: Simulating 1A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 1C: Schema Type Validation Failure (Custom Print Processor Installation via CLI (AN0074))
  * The Log: Exact match of 1A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 1D: Exact Duplicate Event (Custom Print Processor Installation via CLI (AN0074))
  * The Log: Exact duplicate of 1A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

* True Positive 2A: Standard Execution (Custom Print Processor Registry Modification (AN0074-B))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 2B: Malformed JSON Robustness Test (Custom Print Processor Registry Modification (AN0074-B))
  * The Log: Simulating 2A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 2C: Schema Type Validation Failure (Custom Print Processor Registry Modification (AN0074-B))
  * The Log: Exact match of 2A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 2D: Exact Duplicate Event (Custom Print Processor Registry Modification (AN0074-B))
  * The Log: Exact duplicate of 2A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

#### Benign / True Negatives
* Benign 1: Allowed Activity (Custom Print Processor Installation via CLI (AN0074))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

* Benign 2: Allowed Activity (Custom Print Processor Registry Modification (AN0074-B))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

### 6. Raw Telemetry Dataset (OCSF JSON)

#### Benign Telemetry
(See `benign_1.jsonl`)

#### True Positive Telemetry
(See `true_positive_1.jsonl`)
