# e3cc840f-ed19-4f1e-a682-26345cee012b — golden replay datasets

## Files

| File | Description |
|---|---|
| `rule.yml` | The detection rule(s) (Sigma & OCSF) |
| `benign_1.jsonl` | Benign telemetry |
| `true_positive_1.jsonl` | True positive telemetry |

## Replaying

Run the following script to execute the replay (this relies on the test execution engine):
```bash
$ python3 replay.py --datasets e3cc840f-ed19-4f1e-a682-26345cee012b
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1546

* What it is: Event Triggered Execution: WMI Event Subscription. Windows Management Instrumentation (WMI) can be used to register event filters, event consumers, and filter-to-consumer bindings. When a specific system event triggers the filter (e.g., system startup, time elapsed, or user logon), the WMI service executes the consumer (e.g., CommandLineEventConsumer or ActiveScriptEventConsumer) with local system (SYSTEM) privileges. Adversaries exploit WMI event subscriptions to establish persistent, elevated execution flows.
* Log Source Requirements: Endpoint logs capturing process creation and command line arguments, and WMI event subscription logs.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs CLI invocations of wmic.exe or PowerShell cmdlets modifying WMI objects. Sysmon Event IDs 19, 20, and 21 log raw WMI consumer/filter additions.
  - NIDS (Suricata + Zeek): NO. WMI event subscription registration is a local OS management task.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event IDs 19/20/21 (wmi_event)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

### 5. Test Cases (Engine Pipeline Verification)

#### True Positives
* True Positive 1A: Standard Execution (WMI Event Subscription Creation via CLI (AN0024))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 1B: Malformed JSON Robustness Test (WMI Event Subscription Creation via CLI (AN0024))
  * The Log: Simulating 1A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 1C: Schema Type Validation Failure (WMI Event Subscription Creation via CLI (AN0024))
  * The Log: Exact match of 1A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 1D: Exact Duplicate Event (WMI Event Subscription Creation via CLI (AN0024))
  * The Log: Exact duplicate of 1A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

* True Positive 2A: Standard Execution (WMI Event Subscription Event Registration (AN0024-B))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 2B: Malformed JSON Robustness Test (WMI Event Subscription Event Registration (AN0024-B))
  * The Log: Simulating 2A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 2C: Schema Type Validation Failure (WMI Event Subscription Event Registration (AN0024-B))
  * The Log: Exact match of 2A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 2D: Exact Duplicate Event (WMI Event Subscription Event Registration (AN0024-B))
  * The Log: Exact duplicate of 2A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

#### Benign / True Negatives
* Benign 1: Allowed Activity (WMI Event Subscription Creation via CLI (AN0024))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

* Benign 2: Allowed Activity (WMI Event Subscription Event Registration (AN0024-B))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

### 6. Raw Telemetry Dataset (OCSF JSON)

#### Benign Telemetry
(See `benign_1.jsonl`)

#### True Positive Telemetry
(See `true_positive_1.jsonl`)
