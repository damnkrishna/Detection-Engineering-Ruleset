# dd4bf63e-93e5-41f3-82af-56cfbf584e98 — golden replay datasets

## Files

| File | Description |
|---|---|
| `rule.yml` | The detection rule(s) (Sigma & OCSF) |
| `benign_1.jsonl` | Benign telemetry |
| `true_positive_1.jsonl` | True positive telemetry |

## Replaying

Run the following script to execute the replay (this relies on the test execution engine):
```bash
$ python3 replay.py --datasets dd4bf63e-93e5-41f3-82af-56cfbf584e98
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1553.005

* What it is: Subvert Trust Controls: Mark-of-the-Web Bypass. Adversaries bypass Mark-of-the-Web (MOTW) protections by placing malicious payloads inside container or disk image files (such as `.iso`, `.vhd`, `.img`, `.zip`, `.cab`). When these container files are downloaded from the Internet, the operating system assigns them a `Zone.Identifier` stream (MOTW). However, when the user mounts the disk image or extracts the archive, the nested files inside are extracted without the `Zone.Identifier` stream, bypassing security features like SmartScreen or Microsoft Office Protected View. Detection monitors the mounting of disk images or execution of unsigned/untrusted binaries launched from mounted container drives.
* Log Source Requirements: Windows Security Event Log Event ID 4688 or Sysmon process creation logs (Event ID 1) combined with Event ID 11 (File Creation) or System Log Event ID 12 (ISO/VHD mounting events).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs process details, capturing when applications (such as `explorer.exe`) launch disk mounting utilities or run binaries directly from newly mounted drive paths.
    * NIDS (Suricata + Zeek): NO. Disk mounting and local MOTW checks are internal host operating system functions.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

### 5. Test Cases (Engine Pipeline Verification)

#### True Positives
* True Positive 1A: Standard Execution (Subvert Trust Controls - Mark-of-the-Web Bypass via Container Mount (AN0712))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 1B: Malformed JSON Robustness Test (Subvert Trust Controls - Mark-of-the-Web Bypass via Container Mount (AN0712))
  * The Log: Simulating 1A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 1C: Schema Type Validation Failure (Subvert Trust Controls - Mark-of-the-Web Bypass via Container Mount (AN0712))
  * The Log: Exact match of 1A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 1D: Exact Duplicate Event (Subvert Trust Controls - Mark-of-the-Web Bypass via Container Mount (AN0712))
  * The Log: Exact duplicate of 1A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

#### Benign / True Negatives
* Benign 1: Allowed Activity (Subvert Trust Controls - Mark-of-the-Web Bypass via Container Mount (AN0712))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

### 6. Raw Telemetry Dataset (OCSF JSON)

#### Benign Telemetry
(See `benign_1.jsonl`)

#### True Positive Telemetry
(See `true_positive_1.jsonl`)
