# cbdf2001-a189-4db8-bb9a-7c9802cf0031 — golden replay datasets

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
$ python3 replay.py --datasets cbdf2001-a189-4db8-bb9a-7c9802cf0031
```

## Determinism

This dataset is fully deterministic. Timestamps, UUIDs, and generated IDs are statically provided in the `.jsonl` telemetry payload.

### 1. Technique Breakdown: T1106

* What it is: Native API. Adversaries bypass high-level APIs or security agent hooks by invoking Native APIs directly (e.g. via direct syscalls or loading private copies of system DLLs like `ntdll.dll`/`kernel32.dll` from non-standard directories to access unhooked code).
* Log Source Requirements: Sysmon DLL Load events (Event ID 7) and Sysmon Process Access events (Event ID 10).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Non-standard DLL paths and high-privilege virtual memory access handles are monitored.
  - NIDS (Suricata + Zeek): NO. Host-local memory execution.
* Log Sources Covered:
  - Sysmon Event ID 7 (image_load)
  - Sysmon Event ID 10 (process_access)
* Log Sources Missing / Unused:
  - None.

### 4. Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
