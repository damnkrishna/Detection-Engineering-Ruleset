# 57f87938-d149-4d98-ade5-f863627ad343 — golden replay datasets

`RDP Session Hijacking via Service Creation (AN1620-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1563.002

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

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'image_path contains tscon' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'event_id eq 7045' — every other condition holds, so the stage gate rejects the events |

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
