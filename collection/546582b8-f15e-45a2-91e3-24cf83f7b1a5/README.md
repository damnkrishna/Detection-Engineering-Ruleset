# 546582b8-f15e-45a2-91e3-24cf83f7b1a5 — golden replay datasets

`LLMNR/NBT-NS Spoofing Tool Execution (AN1274-A)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1557.001
* What it is: Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay. Adversaries exploit local name resolution protocols (like LLMNR and NBT-NS) to intercept host lookup requests, respond with their own IP, and capture NTLM credential hashes. They can either crack these hashes offline or relay them to other network resources (SMB Relay) to gain unauthorized access.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) and Sysmon Network Connection events (Event ID 3).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Tool launches (e.g. Responder, Inveigh) and processes binding to UDP port 5355/137 or forwarding TCP 445 are visible.
  - NIDS (Suricata + Zeek): YES. Can detect anomalous LLMNR/NBT-NS responses returning non-existent host mappings.
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
| `benign_1.jsonl` | 0 | near-miss value for 'parent_image not_regex .*\Q\setup.exe\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'image_path regex .*\Q\Responder.exe\E$' — every other condition holds, so the stage gate rejects the events |

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
