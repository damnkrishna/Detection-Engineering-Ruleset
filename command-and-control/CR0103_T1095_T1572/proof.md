# Proof — CR0103_T1095_T1572

## Rule

- **Rule ID:** CR0103_T1095_T1572
- **Rule name:** Non-Standard Outbound Port Traffic followed by Local Port Forwarding
- **Rule shape:** THRESHOLD
- **Rule origin / format:** custom / IR_v1
- **Event sources:** [zeek, windows_sysmon]
- **Replay wire:** zeek on topic `replay-events-zeek`
- **Correlation key:** `entity_key`
- **Window:** 900s
- **Max gap:** _(not set)_
- **Stages:** 2
- **MITRE:** [TA0011, TA0005] / [T1095, T1572]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- Stage correlation key: `host.name`
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains Outbound connection on non-standard port | `Zeek::Notice Scan::Address_Scan Outbound connection on non-standard port` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan Outbound connection on no…<br>`hostname`=SEC-WKS-834<br>`agent_ip`=10.42.125.90<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `zeek`, lane key = `10.42.125.90`
- alert `93cd1d3784cd022efd26eccfc16dc131` on lane `entity_key` = `10.42.125.90`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 Anomalous outbound destination port<br>`hostname`=OPS-WKS-833<br>`agent_ip`=10.42.124.90<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `zeek`, lane key = `10.42.124.90`
- alert `d1683d0766c63a0201ec006a2714ce23` on lane `entity_key` = `10.42.124.90`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'signature_name contains Outbound connection on non-standard port' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=technique_id=T1059,technique_name=Command and Scripting I…<br>`hostname`=SEC-WKS-834<br>`agent_ip`=10.42.125.90<br>`severity_id`=3<br>… | signature_name=technique_id=T1059,technique_name=Command and Scripting Interpreter fails 'signature_name contains Outbound connection on non-standard port' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `zeek`, lane key = `10.42.125.90`

## benign_2

**Expected alerts:** 0  
**Construction:** the field 'signature_name' is absent entirely; an absent field is no-match for every operator, so the stage is never entered

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `hostname`=SEC-WKS-834<br>`agent_ip`=10.42.125.90<br>`severity_id`=3<br>`event_uid`=golden\|CR0103_T1095_T1572\|0\|997400<br>… | carries no 'signature_name' at all; evaluateCondition returns no-match for every operator on an absent field, so the stage gate rejects the event |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `zeek`, lane key = `10.42.125.90`

