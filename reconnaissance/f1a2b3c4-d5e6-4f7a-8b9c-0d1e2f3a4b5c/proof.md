# Proof — f1a2b3c4-d5e6-4f7a-8b9c-0d1e2f3a4b5c

## Rule

- **Rule ID:** f1a2b3c4-d5e6-4f7a-8b9c-0d1e2f3a4b5c
- **Rule name:** Rapid Web Path Discovery from Single Source (AN2069)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [reconnaissance] / [T1594]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `http_auth_user` | http_auth_user eq - | `-` |
| `http_status` | http_status eq 403 | `403` |
| `http_request_path` | http_request_path regex ^\/.git\/.* | `/xgit/` |
| `user_agent` | user_agent not_contains Googlebot AND user_agent not_contains Bingbot | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `http_auth_user`=-<br>`http_status`=403<br>`http_request_path`=/xgit/<br>`user_agent`=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.24.30`
- alert `9b99ecc3e09d33787caee0fa3b8805ca` on lane `entity_key` = `10.42.24.30`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `http_auth_user`=-<br>`http_status`=403<br>`http_request_path`=/xenv<br>`user_agent`=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.25.30`
- alert `87d1dba196d014f65e69db98af5a39db` on lane `entity_key` = `10.42.25.30`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'user_agent not_contains Bingbot' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `http_auth_user`=-<br>`http_status`=403<br>`http_request_path`=/xgit/<br>`user_agent`=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537…<br>… | user_agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Bingbot fails 'user_agent not_contains Bingbot' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.24.30`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'http_request_path regex ^\/.git\/.*' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `http_auth_user`=-<br>`http_status`=403<br>`http_request_path`=/api/v1/status<br>`user_agent`=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36<br>… | http_request_path=/api/v1/status fails 'http_request_path regex ^\/.git\/.*' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.24.30`

