# e4c87c0f-f578-463a-8a3a-1ab372eac49c — golden replay datasets

## Files

| File | Description |
|---|---|
| `rule.yml` | The detection rule(s) (Sigma & OCSF) |
| `benign_1.jsonl` | Benign telemetry |
| `true_positive_1.jsonl` | True positive telemetry |

## Replaying

Run the following script to execute the replay (this relies on the test execution engine):
```bash
$ python3 replay.py --datasets e4c87c0f-f578-463a-8a3a-1ab372eac49c
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1091

* What it is: Replication Through Removable Media. Adversaries copy malicious files (such as executables, shortcuts, or scripting payloads) to removable storage devices (like USB flash drives) to compromise other systems, especially air-gapped hosts. The detection monitors execution of scripts, interpreters, or binary utilities directly from removable media paths (e.g. drive paths mapped to typical removable letters like `D:\`, `E:\`, `F:\`, `G:\` etc., instead of the system partition `C:\`).
* Log Source Requirements: Sysmon process creation logs (Event ID 1) and PowerShell script block logs (Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures execution paths on non-system drives. Sysmon Event ID 4104 (Script Block) is effective at catching module loads or scripts referencing drive letters directly.
  * NIDS (Suricata + Zeek): NO. Network sensors have no visibility into local file system execution paths on physical host systems.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

### 5. Test Cases (Engine Pipeline Verification)

#### True Positives
* True Positive 1A: Standard Execution (Removable Media - Execution of Script or Command from Removable Drive (AN0841-A))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 1B: Malformed JSON Robustness Test (Removable Media - Execution of Script or Command from Removable Drive (AN0841-A))
  * The Log: Simulating 1A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 1C: Schema Type Validation Failure (Removable Media - Execution of Script or Command from Removable Drive (AN0841-A))
  * The Log: Exact match of 1A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 1D: Exact Duplicate Event (Removable Media - Execution of Script or Command from Removable Drive (AN0841-A))
  * The Log: Exact duplicate of 1A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

* True Positive 2A: Standard Execution (Removable Media - Suspicious Script Block executing from Removable Drive (AN0841-B))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 2B: Malformed JSON Robustness Test (Removable Media - Suspicious Script Block executing from Removable Drive (AN0841-B))
  * The Log: Simulating 2A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 2C: Schema Type Validation Failure (Removable Media - Suspicious Script Block executing from Removable Drive (AN0841-B))
  * The Log: Exact match of 2A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 2D: Exact Duplicate Event (Removable Media - Suspicious Script Block executing from Removable Drive (AN0841-B))
  * The Log: Exact duplicate of 2A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

#### Benign / True Negatives
* Benign 1: Allowed Activity (Removable Media - Execution of Script or Command from Removable Drive (AN0841-A))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

* Benign 2: Allowed Activity (Removable Media - Suspicious Script Block executing from Removable Drive (AN0841-B))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

### 6. Raw Telemetry Dataset (OCSF JSON)

#### Benign Telemetry
(See `benign_1.jsonl`)

#### True Positive Telemetry
(See `true_positive_1.jsonl`)
