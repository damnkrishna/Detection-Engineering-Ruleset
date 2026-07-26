# Proof — password-spray-success-correlation

## Rule

- **Rule ID:** password-spray-success-correlation
- **Rule name:** Password Spray Followed By Account Compromise
- **Rule shape:** SEQUENCE
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** []
- **Replay wire:** wazuh on topic `replay-events-hids`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 900s
- **Max gap:** _(not set)_
- **Stages:** 2
- **MITRE:** [credential-access, initial-access] / [T1110.003]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 11.0
- `within_seconds` = 900 (deadline for the next stage)
- Stage correlation key: `src_ip`
- Events required: 11

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_type` | event_type eq authentication_failure | `authentication_failure` |

### Stage 1

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 900 (deadline for the next stage)
- Stage correlation key: `src_ip`
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_type` | event_type eq authentication_success | `authentication_success` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 11 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/11 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/11 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/11 |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/11 |
| 5 | 2026-03-02T09:00:04.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/11 |
| 6 | 2026-03-02T09:00:05.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 6/11 |
| 7 | 2026-03-02T09:00:06.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 7/11 |
| 8 | 2026-03-02T09:00:07.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 8/11 |
| 9 | 2026-03-02T09:00:08.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 9/11 |
| 10 | 2026-03-02T09:00:09.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 10/11 |
| 11 | 2026-03-02T09:00:10.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 11/11 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +900s (within_seconds) |
| 12 | 2026-03-02T09:07:40.000Z | 1 | `event_type`=authentication_success<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 12 of 12 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `wazuh`, lane key = `10.42.150.85`
- alert `44740e7451039c7aa6e7c8817b915359` on lane `entity_key` = `10.42.150.85`, match mode `SEQUENCE`, 12 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 11 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=OPS-WKS-258<br>`agent_ip`=10.42.149.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/11 |
| 2 | 2026-03-02T10:00:01.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=OPS-WKS-258<br>`agent_ip`=10.42.149.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/11 |
| 3 | 2026-03-02T10:00:02.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=OPS-WKS-258<br>`agent_ip`=10.42.149.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/11 |
| 4 | 2026-03-02T10:00:03.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=OPS-WKS-258<br>`agent_ip`=10.42.149.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/11 |
| 5 | 2026-03-02T10:00:04.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=OPS-WKS-258<br>`agent_ip`=10.42.149.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/11 |
| 6 | 2026-03-02T10:00:05.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=OPS-WKS-258<br>`agent_ip`=10.42.149.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 6/11 |
| 7 | 2026-03-02T10:00:06.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=OPS-WKS-258<br>`agent_ip`=10.42.149.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 7/11 |
| 8 | 2026-03-02T10:00:07.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=OPS-WKS-258<br>`agent_ip`=10.42.149.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 8/11 |
| 9 | 2026-03-02T10:00:08.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=OPS-WKS-258<br>`agent_ip`=10.42.149.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 9/11 |
| 10 | 2026-03-02T10:00:09.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=OPS-WKS-258<br>`agent_ip`=10.42.149.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 10/11 |
| 11 | 2026-03-02T10:00:10.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=OPS-WKS-258<br>`agent_ip`=10.42.149.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 11/11 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +900s (within_seconds) |
| 12 | 2026-03-02T10:07:40.000Z | 1 | `event_type`=authentication_success<br>`hostname`=OPS-WKS-258<br>`agent_ip`=10.42.149.85<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 12 of 12 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `wazuh`, lane key = `10.42.149.85`
- alert `77d9b1a439081f8912a2cd8559cf0db4` on lane `entity_key` = `10.42.149.85`, match mode `SEQUENCE`, 12 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 1 | `event_type`=authentication_success<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 5 | 2026-03-02T09:00:04.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 6 | 2026-03-02T09:00:05.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 7 | 2026-03-02T09:00:06.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 8 | 2026-03-02T09:00:07.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 9 | 2026-03-02T09:00:08.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 10 | 2026-03-02T09:00:09.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 11 | 2026-03-02T09:00:10.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 12 | 2026-03-02T09:00:11.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 12 of 12 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `wazuh`, lane key = `10.42.150.85`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/11 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/11 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/11 |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/11 |
| 5 | 2026-03-02T09:00:04.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/11 |
| 6 | 2026-03-02T09:00:05.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 6/11 |
| 7 | 2026-03-02T09:00:06.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 7/11 |
| 8 | 2026-03-02T09:00:07.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 8/11 |
| 9 | 2026-03-02T09:00:08.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 9/11 |
| 10 | 2026-03-02T09:00:09.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 10/11 |
| 11 | 2026-03-02T09:00:10.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 11/11 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +900s (within_seconds) |
| 12 | 2026-03-02T09:23:40.000Z | 1 | `event_type`=authentication_success<br>`hostname`=SEC-WKS-259<br>`agent_ip`=10.42.150.85<br>`severity_id`=3<br>… | arrives 1410s after the previous stage completed, past the 900s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 12 of 12 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `wazuh`, lane key = `10.42.150.85`

