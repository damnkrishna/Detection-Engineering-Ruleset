# 11111111-0000-0000-0000-000000000001 — golden replay datasets

`Repeated hostile or IOC DNS/outbound from one host`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 3 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 3 event(s) |
| `benign_1.jsonl` | 0 | count reaches 2 of the required 3 — one event short of the threshold |
| `benign_2.jsonl` | 0 | the final event falls outside the 600s window, so the anchored window restarts and the count never accumulates |

## Replaying

These datasets must be replayed onto **`replay-events-nids`**.
The topic name is not cosmetic: `NormalizedEventDeserializer` selects its parser
from the topic, and `inferSourceFromTopic` derives `NormalizedEvent.source` — the
value `rule.isApplicableTo` gates on. Replayed onto a topic that resolves to a
different source, this rule cannot fire at all.

```
replay --file true_positive_1.jsonl --topic replay-events-nids
```

## Determinism

Timestamps anchor at a fixed origin (`2026-03-02T09:00:00.000Z`), identities derive from the rule id, and event uids are content-derived.
Regenerating from an unchanged rule reproduces these files byte for byte.
