# 5d9f2b38-7c4e-4a91-b6d3-8e1a5f72c946 — golden replay datasets

`XSL Script Execution via WMIC or MSXSL (AN2102)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1220

* What it is: XSL Script Processing. Adversaries may bypass application control and process malicious XSL scripts using wmic.exe (via /format or xsl: arguments) or msxsl.exe to execute embedded JScript or VBScript payloads.
* Log Source Requirements: Sysmon Process Creation (Event ID 1) / Windows Event ID 4688.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Command lines for XSL execution are captured.
  - NIDS (Suricata + Zeek): YES. XSL files fetched from remote URLs via wmic /format:URL produce HTTP traffic.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
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
| `benign_1.jsonl` | 0 | near-miss value for 'cmd_line not_regex (?i)/format:(list\|table\|csv\|hform\|htable\|value\|rawxml\|xml\|mof\|textvaluelist)(?:\s\|$)' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'image_path regex .*\Q\wmic.exe\E$' — every other condition holds, so the stage gate rejects the events |

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
