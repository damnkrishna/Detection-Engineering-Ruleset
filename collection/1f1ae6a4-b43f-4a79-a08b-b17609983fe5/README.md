# 1f1ae6a4-b43f-4a79-a08b-b17609983fe5 — golden replay datasets

`Collection - Data Archiving via Utility (AN0831)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown

* What it is: Archive Collected Data: Archive via Utility. Adversaries compress and package staged data using common archive utilities (such as `7-Zip`, `WinRAR`, or native system tools like `tar.exe` or PowerShell `Compress-Archive` cmdlets) prior to exfiltration. Archiving data reduces payload size for transit and can encrypt contents to bypass content inspection controls (DLP). Detection focuses on identifying command lines invoking archiving commands against sensitive directory structures (like user profiles or web roots).
* Log Source Requirements: Sysmon process creation logs (Event ID 1) capturing command-line parameters.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 provides full command-line arguments, letting security teams audit parameters like `7z.exe a` or `tar.exe -cf`. Wazuh parses these logs.
    * NIDS (Suricata + Zeek): NO. Network sensors have no visibility into local command execution or local file system archiving.

## Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'cmd_line contains  a ' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'image_path regex .*\Q\7z.exe\E$' — every other condition holds, so the stage gate rejects the events |

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
