# d7f8g9h0-1a2b-3c4d-5e6f-7a8b9c0d1e2f — golden replay datasets

## Files

| File | Description |
|---|---|
| `rule.yml` | The detection rule(s) (Sigma & OCSF) |
| `expected.json` | The expected output of the rule |
| `proof.md` | The proof of the rule |
| `benign_1.jsonl` | Benign telemetry |
| `true_positive_1.jsonl` | True positive telemetry |

## Replaying

Run the following script to execute the replay (this relies on the test execution engine):
```bash
$ python3 replay.py --datasets d7f8g9h0-1a2b-3c4d-5e6f-7a8b9c0d1e2f
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1055.004

* What it is: Process Injection: Asynchronous Procedure Call (APC). Adversaries may inject malicious code into a legitimate process by attaching the code to the APC queue of a thread within that process. When the thread enters an alterable state, it executes the queued APC (the malicious payload). This is often achieved via `QueueUserAPC` or `NtQueueApcThread` APIs.
* Log Source Requirements: Sysmon Event ID 8 (CreateRemoteThread), Sysmon Event ID 10 (ProcessAccess), or EDR memory telemetry.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES (Partial). Sysmon does not natively log `QueueUserAPC` directly. However, it logs `ProcessAccess` (Event ID 10) when the injecting process opens a handle to the target, and `CreateRemoteThread` (Event ID 8) if a thread is explicitly created.
    * NIDS (Suricata + Zeek): NO. Memory injection is strictly a local host activity.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
