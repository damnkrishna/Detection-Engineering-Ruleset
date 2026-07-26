# Proof — 7450fcd7-e349-413e-bbfa-e43e76f286fa

## Rule

- **Rule ID:** 7450fcd7-e349-413e-bbfa-e43e76f286fa
- **Rule name:** Reversible Encryption Enabled on User Account (AN1621-A)
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
| `event_id` | event_id eq 4738 | `4738` |
| `user_account_control` | user_account_control in_list [640, 672, 66176, 66208, 2176, 4224, 8320, 0x280, 0x2A0, 0x10280, 0x102A0, 0x880, 0x1080, 0x2080] | `640` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4738<br>`user_account_control`=640<br>`hostname`=FIN-WKS-835<br>`agent_ip`=10.42.126.51 | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.126.51`
- alert `52bb5ed987e2ded5bcb94ee0837a05de` on lane `entity_key` = `10.42.126.51`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=4738<br>`user_account_control`=672<br>`hostname`=SEC-WKS-834<br>`agent_ip`=10.42.125.51 | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.125.51`
- alert `a2854d4a6175f35a39e15fc5bf21d1df` on lane `entity_key` = `10.42.125.51`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'user_account_control in_list [640, 672, 66176, 66208, 2176, 4224, 8320, 0x280, 0x2A0, 0x10280, 0x102A0, 0x880, 0x1080, 0x2080]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4738<br>`user_account_control`=640.bak<br>`hostname`=FIN-WKS-835<br>`agent_ip`=10.42.126.51 | user_account_control=640.bak fails 'user_account_control in_list [640, 672, 66176, 66208, 2176, 4224, 8320, 0x280, 0x2A0, 0x10280, 0x102A0, 0x880, 0x1080, 0x2080]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.126.51`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'event_id eq 4738' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4738.bak<br>`user_account_control`=640<br>`hostname`=FIN-WKS-835<br>`agent_ip`=10.42.126.51 | event_id=4738.bak fails 'event_id eq 4738' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.126.51`

