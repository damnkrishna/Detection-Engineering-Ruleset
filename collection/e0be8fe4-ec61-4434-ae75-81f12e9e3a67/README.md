# e0be8fe4-ec61-4434-ae75-81f12e9e3a67 — golden replay datasets

## Files

| File | Description |
|---|---|
| `rule.yml` | The detection rule(s) (Sigma & OCSF) |
| `benign_1.jsonl` | Benign telemetry |
| `true_positive_1.jsonl` | True positive telemetry |

## Replaying

Run the following script to execute the replay (this relies on the test execution engine):
```bash
$ python3 replay.py --datasets e0be8fe4-ec61-4434-ae75-81f12e9e3a67
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1114

* What it is: Email Collection. Adversaries may search local system directories or Exchange servers for email databases (such as Outlook `.pst` or `.ost` files) to extract sensitive emails, contacts, and calendar items. They copy these files to local staging folders using command-line utilities (like `xcopy.exe` or `robocopy.exe`), PowerShell scripting, or custom malware. They may also set up malicious inbox rules or auto-forwarding settings to exfiltrate email traffic in real time.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) capturing command lines referencing Outlook data files, or Sysmon File Creation/Access events (Event ID 11) capturing access to `.pst`/`.ost` by non-Outlook processes.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs process details, capturing command lines that copy or compress `.pst` or `.ost` files. Sysmon Event ID 11 can be tuned to detect non-Outlook processes opening email store databases.
    * NIDS (Suricata + Zeek): NO. Local database discovery and copying are host-only filesystem operations.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

### 5. Test Cases (Engine Pipeline Verification)

#### True Positives
* True Positive 1A: Standard Execution (Collection - Local Email Database Access and Collection (AN1309))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 1B: Malformed JSON Robustness Test (Collection - Local Email Database Access and Collection (AN1309))
  * The Log: Simulating 1A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 1C: Schema Type Validation Failure (Collection - Local Email Database Access and Collection (AN1309))
  * The Log: Exact match of 1A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 1D: Exact Duplicate Event (Collection - Local Email Database Access and Collection (AN1309))
  * The Log: Exact duplicate of 1A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

#### Benign / True Negatives
* Benign 1: Allowed Activity (Collection - Local Email Database Access and Collection (AN1309))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

### 6. Raw Telemetry Dataset (OCSF JSON)

#### Benign Telemetry
(See `benign_1.jsonl`)

#### True Positive Telemetry
(See `true_positive_1.jsonl`)
