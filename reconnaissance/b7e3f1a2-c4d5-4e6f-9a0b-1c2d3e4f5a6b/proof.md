# Proof — b7e3f1a2-c4d5-4e6f-9a0b-1c2d3e4f5a6b

## Rule

- **Rule ID:** b7e3f1a2-c4d5-4e6f-9a0b-1c2d3e4f5a6b
- **Rule name:** Anomalous HTTP Error Rate from Single Source (AN2069-Error-Spike)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [reconnaissance] / [T1594, T1595.003]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `http_status` | http_status gte 400 | `400` |
| `http_auth_user` | http_auth_user eq - | `-` |
| `user_agent` | user_agent not_contains Googlebot AND user_agent not_contains Bingbot | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `http_status`=400<br>`http_auth_user`=-<br>`user_agent`=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36<br>`hostname`=FIN-WKS-325<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.16.198`
- alert `995fa0092189e31f3cc9e641386cf6ac` on lane `entity_key` = `10.42.16.198`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `http_status`=400<br>`http_auth_user`=-<br>`user_agent`=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36<br>`hostname`=SEC-WKS-324<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.15.198`
- alert `4e549ed6a9679683002f79b5579be4b0` on lane `entity_key` = `10.42.15.198`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'user_agent not_contains Bingbot' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `http_status`=400<br>`http_auth_user`=-<br>`user_agent`=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537…<br>`hostname`=FIN-WKS-325<br>… | user_agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Bingbot fails 'user_agent not_contains Bingbot' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.16.198`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'http_auth_user eq -' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `http_status`=400<br>`http_auth_user`=-.bak<br>`user_agent`=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36<br>`hostname`=FIN-WKS-325<br>… | http_auth_user=-.bak fails 'http_auth_user eq -' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.16.198`

