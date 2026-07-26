# e5b6c7d8-2f3a-4b1c-9d0e-1a2b3c4d5e6f — golden replay datasets

## Files

| File | Description |
|---|---|
| `rule.yml` | The detection rule(s) (Sigma & OCSF) |
| `benign_1.jsonl` | Benign telemetry |
| `true_positive_1.jsonl` | True positive telemetry |

## Replaying

Run the following script to execute the replay (this relies on the test execution engine):
```bash
$ python3 replay.py --datasets e5b6c7d8-2f3a-4b1c-9d0e-1a2b3c4d5e6f
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1558.003

* What it is: Steal or Forge Kerberos Tickets: Kerberoasting. Adversaries abuse the Kerberos protocol to request Service Ticket (TGS) for accounts with Service Principal Names (SPNs) configured—usually highly privileged service accounts. Active Directory grants these tickets encrypted with the service account's password hash. The attacker extracts this ticket from memory and cracks it offline to get the cleartext password.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) tracking execution, and PowerShell script block logs (Sysmon Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 (Process Creation) is excellent for catching the enumeration phase (e.g., using native setspn.exe) or the execution of known tools like Rubeus. Sysmon Event ID 4104 (Script Block) is effective at catching PowerShell-based Kerberoasting implementations.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
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
* True Positive 1A: Standard Execution (Suspicious SPN Enumeration and Kerberoasting Activity via CLI (AN0444-A))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 1B: Malformed JSON Robustness Test (Suspicious SPN Enumeration and Kerberoasting Activity via CLI (AN0444-A))
  * The Log: Simulating 1A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 1C: Schema Type Validation Failure (Suspicious SPN Enumeration and Kerberoasting Activity via CLI (AN0444-A))
  * The Log: Exact match of 1A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 1D: Exact Duplicate Event (Suspicious SPN Enumeration and Kerberoasting Activity via CLI (AN0444-A))
  * The Log: Exact duplicate of 1A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

* True Positive 2A: Standard Execution (Suspicious SPN Enumeration and Kerberoasting Activity via PowerShell Script Block (AN0444-B))
  * The Log: Activity simulating malicious behavior.
  * Expected Outcome: MUST trigger an alert.

* True Positive 2B: Malformed JSON Robustness Test (Suspicious SPN Enumeration and Kerberoasting Activity via PowerShell Script Block (AN0444-B))
  * The Log: Simulating 2A but intentionally omitting the `unmapped` object entirely.
  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.

* True Positive 2C: Schema Type Validation Failure (Suspicious SPN Enumeration and Kerberoasting Activity via PowerShell Script Block (AN0444-B))
  * The Log: Exact match of 2A, but `activity_id` is passed as a string `"1"` instead of an integer `1`.
  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.

* True Positive 2D: Exact Duplicate Event (Suspicious SPN Enumeration and Kerberoasting Activity via PowerShell Script Block (AN0444-B))
  * The Log: Exact duplicate of 2A with the exact same timestamp.
  * Expected Outcome: Tests deduplication window.

#### Benign / True Negatives
* Benign 1: Allowed Activity (Suspicious SPN Enumeration and Kerberoasting Activity via CLI (AN0444-A))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

* Benign 2: Allowed Activity (Suspicious SPN Enumeration and Kerberoasting Activity via PowerShell Script Block (AN0444-B))
  * The Log: Activity matching legitimate patterns.
  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.

### 6. Raw Telemetry Dataset (OCSF JSON)

#### Benign Telemetry
(See `benign_1.jsonl`)

#### True Positive Telemetry
(See `true_positive_1.jsonl`)
