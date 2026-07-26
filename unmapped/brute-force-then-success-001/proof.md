# Proof — brute-force-then-success-001

## Rule

- **Rule ID:** brute-force-then-success-001
- **Rule name:** Brute Force Followed By Successful Login
- **Rule shape:** SEQUENCE
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** []
- **Replay wire:** wazuh on topic `replay-events-hids`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 600s
- **Max gap:** _(not set)_
- **Stages:** 2
- **MITRE:** [credential-access, persistence] / [T1110]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 6.0
- `within_seconds` = 600 (deadline for the next stage)
- Stage correlation key: `src_ip`
- Events required: 6

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_type` | event_type eq authentication_failure | `authentication_failure` |

### Stage 1

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 600 (deadline for the next stage)
- Stage correlation key: `src_ip`
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_type` | event_type eq authentication_success | `authentication_success` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 6 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/6 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/6 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/6 |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/6 |
| 5 | 2026-03-02T09:00:04.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/6 |
| 6 | 2026-03-02T09:00:05.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 6/6 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +600s (within_seconds) |
| 7 | 2026-03-02T09:05:05.000Z | 1 | `event_type`=authentication_success<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 7 of 7 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `wazuh`, lane key = `10.42.92.59`
- alert `eb467e71baf4322ecd9a0ca1a7d00e6a` on lane `entity_key` = `10.42.92.59`, match mode `SEQUENCE`, 7 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 6 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=FIN-WKS-200<br>`agent_ip`=10.42.91.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/6 |
| 2 | 2026-03-02T10:00:01.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=FIN-WKS-200<br>`agent_ip`=10.42.91.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/6 |
| 3 | 2026-03-02T10:00:02.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=FIN-WKS-200<br>`agent_ip`=10.42.91.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/6 |
| 4 | 2026-03-02T10:00:03.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=FIN-WKS-200<br>`agent_ip`=10.42.91.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/6 |
| 5 | 2026-03-02T10:00:04.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=FIN-WKS-200<br>`agent_ip`=10.42.91.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/6 |
| 6 | 2026-03-02T10:00:05.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=FIN-WKS-200<br>`agent_ip`=10.42.91.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 6/6 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +600s (within_seconds) |
| 7 | 2026-03-02T10:05:05.000Z | 1 | `event_type`=authentication_success<br>`hostname`=FIN-WKS-200<br>`agent_ip`=10.42.91.59<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 7 of 7 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `wazuh`, lane key = `10.42.91.59`
- alert `c64949ca1d1242b5ecb7785cad0685e8` on lane `entity_key` = `10.42.91.59`, match mode `SEQUENCE`, 7 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 1 | `event_type`=authentication_success<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 5 | 2026-03-02T09:00:04.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 6 | 2026-03-02T09:00:05.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 7 | 2026-03-02T09:00:06.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 7 of 7 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `wazuh`, lane key = `10.42.92.59`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/6 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/6 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/6 |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/6 |
| 5 | 2026-03-02T09:00:04.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/6 |
| 6 | 2026-03-02T09:00:05.000Z | 0 | `event_type`=authentication_failure<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 6/6 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +600s (within_seconds) |
| 7 | 2026-03-02T09:16:05.000Z | 1 | `event_type`=authentication_success<br>`hostname`=HR-WKS-201<br>`agent_ip`=10.42.92.59<br>`severity_id`=3<br>… | arrives 960s after the previous stage completed, past the 600s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 7 of 7 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `wazuh`, lane key = `10.42.92.59`

