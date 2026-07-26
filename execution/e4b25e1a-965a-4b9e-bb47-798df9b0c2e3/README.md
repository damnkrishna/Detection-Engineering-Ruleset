# e4b25e1a-965a-4b9e-bb47-798df9b0c2e3 — golden replay datasets

## Files

| File | Description |
|---|---|
| `rule.yml` | The detection rule(s) (Sigma & OCSF) |
| `benign_1.jsonl` | Benign telemetry |
| `true_positive_1.jsonl` | True positive telemetry |

## Replaying

Run the following script to execute the replay (this relies on the test execution engine):
```bash
$ python3 replay.py --datasets e4b25e1a-965a-4b9e-bb47-798df9b0c2e3
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1569

* What it is: System Services. Adversaries may abuse system services for execution by modifying existing services or creating new ones. This allows them to execute binaries with `SYSTEM` privileges, load kernel drivers, or establish persistence. Commonly abused tools include `sc.exe`, PowerShell, or direct Win32 API calls (e.g., `CreateServiceW`).
* Log Source Requirements: Process creation logs (Sysmon Event ID 1 / Windows Security Event ID 4688), Windows System Log (Event ID 7045 - Service Created), and Registry modifications (Sysmon ID 12/13).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon tracks `sc.exe` process execution and registry modifications under `HKLM\System\CurrentControlSet\Services`. System Event ID 7045 logs explicit service creation.
    * NIDS (Suricata + Zeek): NO. Service modification is an operating system-level configuration change.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

### 5. Test Cases (Engine Pipeline Verification)

#### True Positives
* True Positive 1A: Standard Execution (System Service Creation or Modification (AN0778))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 1B: Malformed JSON Robustness Test (System Service Creation or Modification (AN0778))
  * The Log: Simulating 1A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 1C: Schema Type Validation Failure (System Service Creation or Modification (AN0778))
  * The Log: Exact match of 1A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 1D: Exact Duplicate Event (System Service Creation or Modification (AN0778))
  * The Log: Exact duplicate of 1A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

#### Benign / True Negatives
* Benign 1: Allowed Activity (System Service Creation or Modification (AN0778))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

### 6. Raw Telemetry Dataset (OCSF JSON)

#### Benign Telemetry
(See `benign_1.jsonl`)

#### True Positive Telemetry
(See `true_positive_1.jsonl`)
