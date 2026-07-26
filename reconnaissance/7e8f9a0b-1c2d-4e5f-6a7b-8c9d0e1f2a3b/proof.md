# Proof — 7e8f9a0b-1c2d-4e5f-6a7b-8c9d0e1f2a3b

## Rule

- **Rule ID:** 7e8f9a0b-1c2d-4e5f-6a7b-8c9d0e1f2a3b
- **Rule name:** Reconnaissance via robots.txt and Sitemap Access (AN2069-Recon-Files)
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
| `http_request_path` | http_request_path contains /robots.txt | `/api/v1/robots.txt` |
| `user_agent` | user_agent not_contains Googlebot AND user_agent not_contains Bingbot AND user_agent not_contains Slurp | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `http_request_path`=/api/v1/robots.txt<br>`user_agent`=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36<br>`hostname`=ENG-WKS-797<br>`agent_ip`=10.42.88.58<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.88.58`
- alert `b29cdaa7eb807d0a828bae6e66380031` on lane `entity_key` = `10.42.88.58`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `http_request_path`=/api/v1/status/sitemap.xml<br>`user_agent`=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36<br>`hostname`=HR-WKS-796<br>`agent_ip`=10.42.87.58<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.87.58`
- alert `6feaeabdda48955f561d6f3c2ef65ea3` on lane `entity_key` = `10.42.87.58`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'user_agent not_contains Slurp' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `http_request_path`=/api/v1/robots.txt<br>`user_agent`=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537…<br>`hostname`=ENG-WKS-797<br>`agent_ip`=10.42.88.58<br>… | user_agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Slurp fails 'user_agent not_contains Slurp' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.88.58`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'http_request_path contains /robots.txt' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `http_request_path`=/api/v1/contoso-robots.txt<br>`user_agent`=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36<br>`hostname`=ENG-WKS-797<br>`agent_ip`=10.42.88.58<br>… | http_request_path=/api/v1/contoso-robots.txt fails 'http_request_path contains /robots.txt' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.88.58`

