# e5f6a7b8-9c0d-1a2b-3c4d-5e6f7a8b9c90 — golden replay datasets

## Files

| File | Description |
|---|---|
| `rule.yml` | The detection rule(s) (Sigma & OCSF) |
| `benign_1.jsonl` | Benign telemetry |
| `true_positive_1.jsonl` | True positive telemetry |

## Replaying

Run the following script to execute the replay (this relies on the test execution engine):
```bash
$ python3 replay.py --datasets e5f6a7b8-9c0d-1a2b-3c4d-5e6f7a8b9c90
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1014

* What it is: Rootkit. Adversaries may install rootkits to hide files, processes, network connections, registry keys, or drivers from operating system APIs. On Windows systems, this is typically achieved by installing custom kernel-mode drivers (SYS files) or exploiting/loading vulnerable signed drivers (BYOVD) to disable Driver Signature Enforcement (DSE) and hook system routines.
* Log Source Requirements:
  * Sysmon Process Creation (Event ID 1) to detect rootkit inspection/installation tools or driver configuration parameters.
* Coverage Check:
  * HIDS (Sysmon): YES. Executing driver loading scripts or anti-rootkit tools generated telemetry.
  * NIDS (Zeek/Suricata): NO. Rootkit operations are completely local to the kernel.
* Log Sources Covered:
  * Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  * None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

### 5. Test Cases (Engine Pipeline Verification)

#### True Positives
* True Positive 1A: Standard Execution (Rootkit Installation or Kernel Driver Bypass Tool Execution (AN2111))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 1B: Malformed JSON Robustness Test (Rootkit Installation or Kernel Driver Bypass Tool Execution (AN2111))
  * The Log: Simulating 1A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 1C: Schema Type Validation Failure (Rootkit Installation or Kernel Driver Bypass Tool Execution (AN2111))
  * The Log: Exact match of 1A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 1D: Exact Duplicate Event (Rootkit Installation or Kernel Driver Bypass Tool Execution (AN2111))
  * The Log: Exact duplicate of 1A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

#### Benign / True Negatives
* Benign 1: Allowed Activity (Rootkit Installation or Kernel Driver Bypass Tool Execution (AN2111))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

### 6. Raw Telemetry Dataset (OCSF JSON)

#### Benign Telemetry
(See `benign_1.jsonl`)

#### True Positive Telemetry
(See `true_positive_1.jsonl`)
