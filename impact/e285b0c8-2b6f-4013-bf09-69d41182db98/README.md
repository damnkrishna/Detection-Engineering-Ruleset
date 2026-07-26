# e285b0c8-2b6f-4013-bf09-69d41182db98 — golden replay datasets

## Files

| File | Description |
|---|---|
| `rule.yml` | The detection rule(s) (Sigma & OCSF) |
| `benign_1.jsonl` | Benign telemetry |
| `true_positive_1.jsonl` | True positive telemetry |

## Replaying

Run the following script to execute the replay (this relies on the test execution engine):
```bash
$ python3 replay.py --datasets e285b0c8-2b6f-4013-bf09-69d41182db98
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1565.002

* What it is: Transmitted Data Manipulation. Adversaries may manipulate data transmitted over network connections to interfere with communications, typically by altering network routing or proxy configurations to redirect traffic to local loopback addresses or unauthorized gateways.
* Log Source Requirements: Endpoint logs capturing process creation (Sysmon Event ID 1 / Windows Security Event ID 4688).
* Coverage Check:
    * HIDS: YES. Sysmon Event ID 1 logs process executions.
    * NIDS: NO.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

### 5. Test Cases (Engine Pipeline Verification)

#### True Positives
* True Positive 1A: Standard Execution (Transmitted Data Manipulation - Config Network Alteration via CLI (AN0702-B))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 1B: Malformed JSON Robustness Test (Transmitted Data Manipulation - Config Network Alteration via CLI (AN0702-B))
  * The Log: Simulating 1A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 1C: Schema Type Validation Failure (Transmitted Data Manipulation - Config Network Alteration via CLI (AN0702-B))
  * The Log: Exact match of 1A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 1D: Exact Duplicate Event (Transmitted Data Manipulation - Config Network Alteration via CLI (AN0702-B))
  * The Log: Exact duplicate of 1A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

#### Benign / True Negatives
* Benign 1: Allowed Activity (Transmitted Data Manipulation - Config Network Alteration via CLI (AN0702-B))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

### 6. Raw Telemetry Dataset (OCSF JSON)

#### Benign Telemetry
(See `benign_1.jsonl`)

#### True Positive Telemetry
(See `true_positive_1.jsonl`)
