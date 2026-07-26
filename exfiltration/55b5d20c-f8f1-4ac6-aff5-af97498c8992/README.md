# 55b5d20c-f8f1-4ac6-aff5-af97498c8992 — golden replay datasets

`Exfiltration - Outbound Network Connection from Suspicious Path (AN0988)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1041

* What it is: Exfiltration Over C2 Channel. Adversaries exfiltrate stolen data by transmitting it directly through their existing command-and-control (C2) communication channel. This avoids establishing new outbound network connections that might trigger perimeter firewall alerts. Host-local detection involves identifying suspicious processes running from non-standard folders (like temp paths, user profile folders) or running as hidden services initiating network connections (Sysmon Event ID 3) and transmitting large payloads.
* Log Source Requirements: Sysmon network connection logs (Event ID 3) combined with initiating process metadata (Sysmon Event ID 1).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 3 logs outbound network connections along with the initiating application's file path. Wazuh aggregates these and alerts on connections from high-risk paths.
    * NIDS (Suricata + Zeek): YES. Network monitoring can track anomalous traffic volume spikes or beaconing behavior targeting C2 endpoints.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'dst_ip not_starts_with 169.254.' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'image_path contains \AppData\Local\Temp\' — every other condition holds, so the stage gate rejects the events |

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
