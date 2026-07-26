# 59f67487-d5fd-4037-a8a8-e0cbbca65da1 — golden replay datasets

`Spearphishing Attachment - Execution of Process from Mail Attachment Cache (AN0655-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1566.001

* What it is: Phishing: Spearphishing Attachment. Adversaries send emails containing malicious attachments (such as macro-enabled spreadsheets, script files, shortcuts, or disk images like `.iso` and `.img`) to establish a foothold. When the user opens the email or attempts to view the attachment, the email client (e.g., Outlook) writes the attachment file to the local disk (specifically to temporary download paths or temporary internet cache directories).
* Log Source Requirements: Sysmon File Creation logs (Event ID 11) and Sysmon process creation logs (Event ID 1).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 11 records the mail client process writing to disk. Sysmon Event ID 1 records the execution of processes directly from the mail attachment cache directory.
  * NIDS (Suricata + Zeek): YES. Network intrusion sensors analyze SMTP/IMAP streams and extract attachments, but endpoint-based process execution logs are necessary to verify execution.
* Log Sources Covered:
  - Sysmon Event ID 11 (file_event)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Spearphishing attachment deployment and execution can be detected using file creation and process creation logs.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'image_path contains \Content.Outlook\' — every other condition holds, so the stage gate rejects the events |
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
