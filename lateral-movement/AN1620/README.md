# AN1620 — golden replay datasets

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
$ python3 replay.py --datasets AN1620
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1563.002

* What it is: RDP Hijacking (sub-technique of Remote Service Session Hijacking). Adversaries may hijack an existing Remote Desktop Protocol (RDP) session without needing the target user's password. A common method on Windows involves running the native Terminal Services Session Connection utility `tscon.exe` under high privilege (`SYSTEM` context, e.g. via scheduled task or system service). The attacker uses `tscon.exe <session_id> /dest:<session_name>` to attach the active session of a logged-on user to their own current session, immediately taking control of the user's desktop.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs process paths (`tscon.exe`) and command line parameters including the `/dest` parameter.
    * NIDS (Suricata + Zeek): NO. The actual transfer of sessions using `tscon.exe` is handled internally by the Session Manager service (`smss.exe`) and Terminal Services on the host. It produces no direct network traffic during the session swap itself.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Windows System Log Event ID 7045 (system)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
