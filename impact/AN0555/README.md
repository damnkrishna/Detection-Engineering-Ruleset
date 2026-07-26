# AN0555 — golden replay datasets

`Stored Office Document Modification by Scripting Host (AN0555)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1565.001

* What it is: Stored Data Manipulation. Adversaries modify business-critical stored data (such as Office documents, PDF sheets, or text databases) to disrupt operations, alter business communications, or plant malicious macros/payloads. Under Windows, they use command-line shells or scripting engines to scan directories and modify file contents. Detections monitor local file modification events targeting document formats (.docx, .xlsx, .pdf) by execution shells, as well as command-line configurations referencing these extensions by scripting hosts.
* Log Source Requirements: Endpoint logs capturing file creation, modification, or write events (Sysmon Event ID 11 / Windows Security Event ID 4663) and process creation logs (Sysmon Event ID 1 / Windows Security Event ID 4688).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 11 logs file path names, extensions, and writing processes. Sysmon Event ID 1 captures command-line parameters containing document extensions executed by scripting interpreters.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 11 (file_event)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Stored office document modification activity can be detected using file event and process creation logs.

## Blind Spots & Tuning

- Legitimate enterprise automation scripts performing automated report compilation, PDF generation, or document migration.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'file_path regex .+\Q.docx\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'image_path regex .+\Q\powershell.exe\E$' — every other condition holds, so the stage gate rejects the events |

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
