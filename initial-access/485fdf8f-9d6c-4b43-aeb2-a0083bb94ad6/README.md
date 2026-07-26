# 485fdf8f-9d6c-4b43-aeb2-a0083bb94ad6 — golden replay datasets

`Phishing - Suspicious Child Process Spawned by Mail Client (AN0188-A)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1566
* What it is: Phishing. Adversaries send malicious attachments or links through email (e.g., via Outlook) or messaging tools to gain initial access to target environments. When the user opens the attachment, it spawns script interpreters (like PowerShell, cmd, or mshta) or launching programs to run external code.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) capturing parent-child process execution patterns, and Sysmon file creation logs (Event ID 11).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures email clients spawning scripting tools or office productivity suites. Sysmon Event ID 11 captures files written by mail clients.
  * NIDS (Suricata + Zeek): YES. Network logs can flag SMTP/IMAP attachments with suspicious extensions or connections to known phishing domains.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Phishing activity can be detected using process creation and file creation logs.

## Blind Spots & Tuning
- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'image_path regex .*\Q\cmd.exe\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'parent_image regex .*\Q\outlook.exe\E$' — every other condition holds, so the stage gate rejects the events |

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
