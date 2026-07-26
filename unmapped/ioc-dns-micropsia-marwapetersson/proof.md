# Proof — ioc-dns-micropsia-marwapetersson

## Rule

- **Rule ID:** ioc-dns-micropsia-marwapetersson
- **Rule name:** APT-C-23 MICROPSIA C2 Domain in DNS Lookup
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [suricata]
- **Replay wire:** suricata on topic `replay-events-nids`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [command-and-control] / [T1071.004]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains MICROPSIA Variant CnC Domain in DNS Lookup | `ET MALWARE Observed Suspicious Outbound Connection MICROPSIA Variant CnC Domain in DNS Lookup` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection MICROP…<br>`hostname`=OPS-WKS-528<br>`agent_ip`=10.42.19.22<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.19.22`
- alert `8f5737edc7f1492be227470b9bcc334c` on lane `entity_key` = `10.42.19.22`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `dns_query`=C:\Windows\System32 marwapetersson.info<br>`hostname`=SEC-WKS-529<br>`agent_ip`=10.42.20.22<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.20.22`
- alert `e969f27df387438c7589707171b118bc` on lane `entity_key` = `10.42.20.22`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'signature_name contains MICROPSIA Variant CnC Domain in DNS Lookup' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=technique_id=T1059,technique_name=Command and Scripting I…<br>`hostname`=OPS-WKS-528<br>`agent_ip`=10.42.19.22<br>`severity_id`=3<br>… | signature_name=technique_id=T1059,technique_name=Command and Scripting Interpreter fails 'signature_name contains MICROPSIA Variant CnC Domain in DNS Lookup' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.19.22`

## benign_2

**Expected alerts:** 0  
**Construction:** the field 'signature_name' is absent entirely; an absent field is no-match for every operator, so the stage is never entered

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `hostname`=OPS-WKS-528<br>`agent_ip`=10.42.19.22<br>`severity_id`=3<br>`event_uid`=golden\|ioc-dns-micropsia-marwapetersson\|0\|552400<br>… | carries no 'signature_name' at all; evaluateCondition returns no-match for every operator on an absent field, so the stage gate rejects the event |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.19.22`

