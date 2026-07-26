# Proof — CR0109_T1568_T1218

## Rule

- **Rule ID:** CR0109_T1568_T1218
- **Rule name:** Dynamic DNS Domain Request followed by certutil Download
- **Rule shape:** THRESHOLD
- **Rule origin / format:** custom / IR_v1
- **Event sources:** [zeek, windows_sysmon]
- **Replay wire:** zeek on topic `replay-events-zeek`
- **Correlation key:** `entity_key`
- **Window:** 900s
- **Max gap:** _(not set)_
- **Stages:** 2
- **MITRE:** [TA0011, TA0002] / [T1568, T1218.007]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- Stage correlation key: `host.name`
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains Dynamic DNS query | `Zeek::Notice Scan::Address_Scan Dynamic DNS query` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan Dynamic DNS query<br>`hostname`=HR-WKS-496<br>`agent_ip`=10.42.187.115<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `zeek`, lane key = `10.42.187.115`
- alert `0edc91beece6a8fa96c486542e29540e` on lane `entity_key` = `10.42.187.115`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 DDNS resolution<br>`hostname`=FIN-WKS-495<br>`agent_ip`=10.42.186.115<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `zeek`, lane key = `10.42.186.115`
- alert `f84f0f5fe53c04ec1ac4598b9db9505b` on lane `entity_key` = `10.42.186.115`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'signature_name contains Dynamic DNS query' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=technique_id=T1059,technique_name=Command and Scripting I…<br>`hostname`=HR-WKS-496<br>`agent_ip`=10.42.187.115<br>`severity_id`=3<br>… | signature_name=technique_id=T1059,technique_name=Command and Scripting Interpreter fails 'signature_name contains Dynamic DNS query' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `zeek`, lane key = `10.42.187.115`

## benign_2

**Expected alerts:** 0  
**Construction:** the field 'signature_name' is absent entirely; an absent field is no-match for every operator, so the stage is never entered

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `hostname`=HR-WKS-496<br>`agent_ip`=10.42.187.115<br>`severity_id`=3<br>`event_uid`=golden\|CR0109_T1568_T1218\|0\|81600<br>… | carries no 'signature_name' at all; evaluateCondition returns no-match for every operator on an absent field, so the stage gate rejects the event |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `zeek`, lane key = `10.42.187.115`

