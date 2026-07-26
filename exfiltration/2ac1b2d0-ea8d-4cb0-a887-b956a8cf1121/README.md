# 2ac1b2d0-ea8d-4cb0-a887-b956a8cf1121 — golden replay datasets

`Bluetooth Device Connection or Configuration (AN0212-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown

* What it is: Exfiltration Over Other Network Medium. Adversaries bypass corporate firewall and proxy monitors by exfiltrating data through non-primary network interfaces connected directly to the internet (such as local WiFi hotspots, mobile cellular adapters, or Bluetooth links). Detections focus on identifying command-line configurations of wireless adapters or registry modifications of Bluetooth drivers, indicating out-of-band network staging.
* Log Source Requirements: Endpoint logs capturing process creation and registry modifications.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs commands querying/configuring wireless interfaces, and Event ID 13 (Registry Set) logs Bluetooth service configuration modifications.
* NIDS (Suricata + Zeek): NO. Traffic bypasses corporate security boundary proxies and gateways.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
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
| `benign_1.jsonl` | 0 | near-miss value for 'target_object contains \System\CurrentControlSet\Services\BTHPORT\' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | the field 'target_object' is absent entirely; an absent field is no-match for every operator, so the stage is never entered |

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
