# e31724af-96d1-4bbd-bc0c-579e800002f4 — golden replay datasets

## Files

| File | Description |
|---|---|
| `rule.yml` | The detection rule(s) (Sigma & OCSF) |
| `benign_1.jsonl` | Benign telemetry |
| `true_positive_1.jsonl` | True positive telemetry |

## Replaying

Run the following script to execute the replay (this relies on the test execution engine):
```bash
$ python3 replay.py --datasets e31724af-96d1-4bbd-bc0c-579e800002f4
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1557

* What it is: Adversary-in-the-Middle (AiTM). Adversaries may position themselves between two or more communicating devices to monitor, intercept, or modify data. Common tools like Cain & Abel, Ettercap, or Netcut can execute ARP spoofing.
* Log Source Requirements: Endpoint logs capturing process creation (Sysmon Event ID 1 / Windows Security Event ID 4688).
* Coverage Check:
    * HIDS: YES. Sysmon Event ID 1 logs process executions.
    * NIDS: NO.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

### 5. Test Cases (Engine Pipeline Verification)

#### True Positives
* True Positive 1A: Standard Execution (AiTM - Suspicious ARP Spoofing Utility Execution (AN0823-A))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 1B: Malformed JSON Robustness Test (AiTM - Suspicious ARP Spoofing Utility Execution (AN0823-A))
  * The Log: Simulating 1A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 1C: Schema Type Validation Failure (AiTM - Suspicious ARP Spoofing Utility Execution (AN0823-A))
  * The Log: Exact match of 1A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 1D: Exact Duplicate Event (AiTM - Suspicious ARP Spoofing Utility Execution (AN0823-A))
  * The Log: Exact duplicate of 1A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

#### Benign / True Negatives
* Benign 1: Allowed Activity (AiTM - Suspicious ARP Spoofing Utility Execution (AN0823-A))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

### 6. Raw Telemetry Dataset (OCSF JSON)

#### Benign Telemetry
(See `benign_1.jsonl`)

#### True Positive Telemetry
(See `true_positive_1.jsonl`)
