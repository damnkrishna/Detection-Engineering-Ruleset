# e093e8c8-59a4-4b72-a6cd-0c14c5d050a9 — golden replay datasets

## Files

| File | Description |
|---|---|
| `rule.yml` | The detection rule(s) (Sigma & OCSF) |
| `benign_1.jsonl` | Benign telemetry |
| `true_positive_1.jsonl` | True positive telemetry |

## Replaying

Run the following script to execute the replay (this relies on the test execution engine):
```bash
$ python3 replay.py --datasets e093e8c8-59a4-4b72-a6cd-0c14c5d050a9
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1496.002

* What it is: Resource Hijacking: Joint Bandwidth Hijacking. Adversaries hijack a compromised system's network bandwidth to run proxy services (known as proxyjacking, e.g., Honeygain, EarnApp, PacketStream) or execute botnet-driven scanning tasks. This allows the attacker to monetize the victim's internet connection or route malicious traffic through their IP space, resulting in severe performance degradation and reputation blacklisting. Detections monitor the execution of known bandwidth-sharing or high-volume scanning binaries and their associated network activity.
* Log Source Requirements: Endpoint logs capturing process creation (Sysmon Event ID 1 / Windows Security Event ID 4688) and network connection logs (Sysmon Event ID 3).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 logs the execution of proxyjacking client files. Sysmon Event ID 3 captures outbound socket connections to bandwidth-sharing coordinator nodes.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Proxyjacking and bandwidth hijacking activity can be detected using process creation and network connection logs.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

### 5. Test Cases (Engine Pipeline Verification)

#### True Positives
* True Positive 1A: Standard Execution (Execution of Bandwidth Hijacking or Proxyjacking Software via CLI (AN0080-A))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 1B: Malformed JSON Robustness Test (Execution of Bandwidth Hijacking or Proxyjacking Software via CLI (AN0080-A))
  * The Log: Simulating 1A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 1C: Schema Type Validation Failure (Execution of Bandwidth Hijacking or Proxyjacking Software via CLI (AN0080-A))
  * The Log: Exact match of 1A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 1D: Exact Duplicate Event (Execution of Bandwidth Hijacking or Proxyjacking Software via CLI (AN0080-A))
  * The Log: Exact duplicate of 1A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

* True Positive 2A: Standard Execution (Execution of Bandwidth Hijacking or Proxyjacking Software via Network Connection (AN0080-B))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 2B: Malformed JSON Robustness Test (Execution of Bandwidth Hijacking or Proxyjacking Software via Network Connection (AN0080-B))
  * The Log: Simulating 2A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 2C: Schema Type Validation Failure (Execution of Bandwidth Hijacking or Proxyjacking Software via Network Connection (AN0080-B))
  * The Log: Exact match of 2A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 2D: Exact Duplicate Event (Execution of Bandwidth Hijacking or Proxyjacking Software via Network Connection (AN0080-B))
  * The Log: Exact duplicate of 2A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

#### Benign / True Negatives
* Benign 1: Allowed Activity (Execution of Bandwidth Hijacking or Proxyjacking Software via CLI (AN0080-A))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

* Benign 2: Allowed Activity (Execution of Bandwidth Hijacking or Proxyjacking Software via Network Connection (AN0080-B))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

### 6. Raw Telemetry Dataset (OCSF JSON)

#### Benign Telemetry
(See `benign_1.jsonl`)

#### True Positive Telemetry
(See `true_positive_1.jsonl`)
