# Proof — CR0095_T1563_T1078

## Rule

- **Rule ID:** CR0095_T1563_T1078
- **Rule name:** Administrative RDP Session Hijacking via tscon.exe
- **Rule shape:** THRESHOLD
- **Rule origin / format:** custom / IR_v1
- **Event sources:** [zeek, windows_sysmon]
- **Replay wire:** zeek on topic `replay-events-zeek`
- **Correlation key:** `entity_key`
- **Window:** 1800s
- **Max gap:** _(not set)_
- **Stages:** 2
- **MITRE:** [TA0008, TA0004] / [T1563.002, T1078]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- Stage correlation key: `host.name`
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains RDP connection | `Zeek::Notice Scan::Address_Scan RDP connection` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan RDP connection<br>`hostname`=ENG-WKS-107<br>`agent_ip`=10.42.198.81<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; carries logon type 3 (network) — the remote-auth evidence this rule is gated on |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `zeek`, lane key = `10.42.198.81`
- alert `559f3fbda68c7e7aae03bcaf8aada351` on lane `entity_key` = `10.42.198.81`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 RDP session established<br>`hostname`=HR-WKS-106<br>`agent_ip`=10.42.197.81<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; carries logon type 3 (network) — the remote-auth evidence this rule is gated on |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `zeek`, lane key = `10.42.197.81`
- alert `8cb7a6087d578e89c3c34a8a48637401` on lane `entity_key` = `10.42.197.81`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'signature_name contains RDP connection' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=technique_id=T1059,technique_name=Command and Scripting I…<br>`hostname`=ENG-WKS-107<br>`agent_ip`=10.42.198.81<br>`severity_id`=3<br>… | signature_name=technique_id=T1059,technique_name=Command and Scripting Interpreter fails 'signature_name contains RDP connection' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `zeek`, lane key = `10.42.198.81`

## benign_2

**Expected alerts:** 0  
**Construction:** the field 'signature_name' is absent entirely; an absent field is no-match for every operator, so the stage is never entered

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `hostname`=ENG-WKS-107<br>`agent_ip`=10.42.198.81<br>`severity_id`=3<br>`event_uid`=golden\|CR0095_T1563_T1078\|0\|614900<br>… | carries no 'signature_name' at all; evaluateCondition returns no-match for every operator on an absent field, so the stage gate rejects the event |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `zeek`, lane key = `10.42.198.81`

