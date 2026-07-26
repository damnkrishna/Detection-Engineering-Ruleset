# 2a8c5e71-3f9b-4d26-c8e1-7b4d9a15f263 — golden replay datasets

`Credential String Search in Files and Registry (AN2103)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown

* What it is: Unsecured Credentials. Adversaries may search for unsecured credentials stored in files, registry, or configuration files on compromised systems to obtain them for lateral movement or privilege escalation.
* Log Source Requirements: Sysmon Process Creation (Event ID 1) / Windows Event ID 4688.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Command-line credential searches are captured.
  - NIDS (Suricata + Zeek): NO. Host-local file access.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

## Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'parent_image not_regex .*\Q\SenseCnfg.exe\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'image_path regex .*\Q\findstr.exe\E$' — every other condition holds, so the stage gate rejects the events |

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
