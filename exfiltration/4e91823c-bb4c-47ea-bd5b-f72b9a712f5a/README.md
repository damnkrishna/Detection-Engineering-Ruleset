# 4e91823c-bb4c-47ea-bd5b-f72b9a712f5a — golden replay datasets

`CLI Alternative Protocol Utility Execution (AN0367-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1048

* What it is: Exfiltration Over Alternative Protocol. Adversaries exfiltrate collected data over a protocol different from the primary C2 channel. Typical alternative protocols include FTP, SMTP (email), external SMB shares, or DNS queries. Detections target processes initiating connections over ports associated with these protocols, or CLI execution of transfer utilities like ftp.exe or curl.exe.
* Log Source Requirements: Endpoint logs capturing network connection events and process creation events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 3 (Network Connection) logs outbound connections over alternative protocols (ports 21, 25, 445) initiated by execution shells, and Event ID 1 (Process Creation) captures execution of transfer utilities.
* NIDS (Suricata + Zeek): YES. Network boundary logs capture protocol handshakes and data lengths.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 3 (network_connection)
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
| `benign_1.jsonl` | 0 | near-miss value for 'image_path regex .*\Q\ftp.exe\E$' — every other condition holds, so the stage gate rejects the events |
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
