# DNS_NXDOMAIN_RATIO_ANOMALY — golden replay datasets

`≥15 NXDOMAIN responses from single host in 5 minutes — DGA C2 lookup pattern, behavior-driven, no signature dependency (T1568.002)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `rule.yml` | N/A | Correlation Rule definition (IR_v1 JSON format) |
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 15 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 15 event(s) |
| `benign_1.jsonl` | 0 | count reaches 14 of the required 15 — one event short of the threshold |
| `benign_2.jsonl` | 0 | the final event falls outside the 300s window, so the anchored window restarts and the count never accumulates |

## Replaying

These datasets must be replayed onto **`replay-events-zeek`**.
The topic name is not cosmetic: `NormalizedEventDeserializer` selects its parser
from the topic, and `inferSourceFromTopic` derives `NormalizedEvent.source` — the
value `rule.isApplicableTo` gates on. Replayed onto a topic that resolves to a
different source, this rule cannot fire at all.

```
replay --file true_positive_1.jsonl --topic replay-events-zeek
```

## Determinism

Timestamps anchor at a fixed origin (`2026-03-02T09:00:00.000Z`), identities derive from the rule id, and event uids are content-derived.
Regenerating from an unchanged rule reproduces these files byte for byte.
