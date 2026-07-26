# SQL_INJECTION_EXFIL — golden replay datasets

`SQL injection followed by data exfiltration (Splunk: Web Application Attack story)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `rule.yml` | N/A | Correlation Rule definition (IR_v1 JSON format) |
| `true_positive_1.jsonl` | 1 | SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s) |
| `benign_1.jsonl` | 0 | stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0 |
| `benign_2.jsonl` | 0 | inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded |

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
