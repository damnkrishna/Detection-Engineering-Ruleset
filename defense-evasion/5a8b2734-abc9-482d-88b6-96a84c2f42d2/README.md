# 5a8b2734-abc9-482d-88b6-96a84c2f42d2 — golden replay datasets

`Disable or Modify Tools - Spoof Tool UI (AN0868)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1685.003

* What it is: Disable or Modify Tools: Modify or Spoof Tool UI. Adversaries may modify or spoof the user interface of security tools to hide their activities. This involves showing a false "healthy" or "active" status for tools like Windows Defender, even when the underlying security services (e.g., WinDefend, MsMpEng.exe) are stopped or disabled.
* Log Source Requirements: Process creation logs (Sysmon Event ID 1 / Windows Security Event ID 4688) and System logs for service states.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 can monitor the execution of UI components, and Windows System logs can monitor the actual service states (Event ID 7036 for service stops).
    * NIDS (Suricata + Zeek): NO. UI spoofing and service state manipulation are strictly host-level activities.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'cmd_line contains spoof' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'image_path regex .*\Q\SecurityHealthSystray.exe\E$' — every other condition holds, so the stage gate rejects the events |

## Replaying

These datasets must be replayed onto **`replay-events-sysmon`**.
The topic name is not cosmetic: `NormalizedEventDeserializer` selects its parser
from the topic, and `inferSourceFromTopic` derives `NormalizedEvent.source` — the
value `rule.isApplicableTo` gates on. Replayed onto a topic that resolves to a
different source, this rule cannot fire at all.

```
replay --file true_positive_1.jsonl --topic replay-events-sysmon
```

## Determinism

Timestamps anchor at a fixed origin (`2026-03-02T09:00:00.000Z`), identities derive from the rule id, and event uids are content-derived.
Regenerating from an unchanged rule reproduces these files byte for byte.
