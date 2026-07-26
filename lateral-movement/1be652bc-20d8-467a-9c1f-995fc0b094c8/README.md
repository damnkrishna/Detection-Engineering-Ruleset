# 1be652bc-20d8-467a-9c1f-995fc0b094c8 — golden replay datasets

`Executable Run from Shared Storage (AN1298-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown

* What it is: Shared Content. Adversaries may deliver payloads to a system by tainting content that is shared across systems, e.g., in shared network directories or repositories. An administrative network share (such as C$, ADMIN$, or IPC$) is often used by lateral movement tools and adversaries to copy binaries, scripts, or shortcut files. Once dropped on the shared repository or administrative volume, these files can be executed by target hosts through remote scheduled tasks, remote service control, or manual user interaction.
* Log Source Requirements: Endpoint file creation events (e.g. Sysmon Event ID 11 / Windows Security Event ID 4663) monitoring writes to shared folders or administrative volumes.
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 11 logs the creation of files, their target paths, writing processes, and extensions.
  * NIDS (Suricata + Zeek): NO. While NIDS can track SMB file transfers, detecting file creation events on host volumes (like specific administrative shares mapped locally) requires host-based filesystem auditing.
* Log Sources Covered:
  - Sysmon Event ID 11 (file_event)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Dropping and executing tainted shared content can be detected using file event and process creation logs.

## Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'image_path not_starts_with C:\' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | the field 'image_path' is absent entirely; an absent field is no-match for every operator, so the stage is never entered |

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
