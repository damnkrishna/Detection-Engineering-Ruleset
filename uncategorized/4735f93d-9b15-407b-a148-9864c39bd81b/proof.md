# Proof — 4735f93d-9b15-407b-a148-9864c39bd81b

## Rule

- **Rule ID:** 4735f93d-9b15-407b-a148-9864c39bd81b
- **Rule name:** Reversible Encryption Enabled via Active Directory Attribute modification (AN1621-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [] / [T1556.005]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id eq 5136 | `5136` |
| `attribute_ldapdisplay_name` | attribute_ldapdisplay_name eq userAccountControl | `userAccountControl` |
| `attribute_value` | attribute_value in_list [640, 672, 66176, 66208, 2176, 4224, 8320, 0x280, 0x2A0, 0x10280, 0x102A0, 0x880, 0x1080, 0x2080] | `640` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=5136<br>`attribute_ldapdisplay_name`=userAccountControl<br>`attribute_value`=640<br>`hostname`=FIN-WKS-125<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.16.111`
- alert `a0c8b08fa5c80c70f4cb09bc9b7fcefd` on lane `entity_key` = `10.42.16.111`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=5136<br>`attribute_ldapdisplay_name`=userAccountControl<br>`attribute_value`=672<br>`hostname`=HR-WKS-126<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.17.111`
- alert `ff3286e441e960f0befb9ba50079a9c2` on lane `entity_key` = `10.42.17.111`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'attribute_value in_list [640, 672, 66176, 66208, 2176, 4224, 8320, 0x280, 0x2A0, 0x10280, 0x102A0, 0x880, 0x1080, 0x2080]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=5136<br>`attribute_ldapdisplay_name`=userAccountControl<br>`attribute_value`=640.bak<br>`hostname`=FIN-WKS-125<br>… | attribute_value=640.bak fails 'attribute_value in_list [640, 672, 66176, 66208, 2176, 4224, 8320, 0x280, 0x2A0, 0x10280, 0x102A0, 0x880, 0x1080, 0x2080]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.16.111`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'attribute_ldapdisplay_name eq userAccountControl' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=5136<br>`attribute_ldapdisplay_name`=userAccountControl.bak<br>`attribute_value`=640<br>`hostname`=FIN-WKS-125<br>… | attribute_ldapdisplay_name=userAccountControl.bak fails 'attribute_ldapdisplay_name eq userAccountControl' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.16.111`

