# Proof — 0b432959-f29d-4506-8f8d-742a883368e5

## Rule

- **Rule ID:** 0b432959-f29d-4506-8f8d-742a883368e5
- **Rule name:** Windows Resource Exhaustion Diagnosis Event (AN1012-A)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [impact] / [T1499.001]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id eq 2004 | `2004` |
| `log_channel` | log_channel eq Microsoft-Windows-Resource-Exhaustion-Detector | `Microsoft-Windows-Resource-Exhaustion-Detector` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=2004<br>`log_channel`=Microsoft-Windows-Resource-Exhaustion-Detector<br>`hostname`=HR-WKS-551<br>`agent_ip`=10.42.142.188 | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.142.188`
- alert `739c3d446d0407df4c523827298373c0` on lane `entity_key` = `10.42.142.188`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=2004<br>`log_channel`=Microsoft-Windows-Resource-Exhaustion-Detector<br>`hostname`=ENG-WKS-552<br>`agent_ip`=10.42.143.188 | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.143.188`
- alert `df975c23e8983e0aade61a38648ef77a` on lane `entity_key` = `10.42.143.188`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'log_channel eq Microsoft-Windows-Resource-Exhaustion-Detector' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=2004<br>`log_channel`=Microsoft-Windows-Resource-Exhaustion-Detector.bak<br>`hostname`=HR-WKS-551<br>`agent_ip`=10.42.142.188 | log_channel=Microsoft-Windows-Resource-Exhaustion-Detector.bak fails 'log_channel eq Microsoft-Windows-Resource-Exhaustion-Detector' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.142.188`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'event_id eq 2004' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=2004.bak<br>`log_channel`=Microsoft-Windows-Resource-Exhaustion-Detector<br>`hostname`=HR-WKS-551<br>`agent_ip`=10.42.142.188 | event_id=2004.bak fails 'event_id eq 2004' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.142.188`

