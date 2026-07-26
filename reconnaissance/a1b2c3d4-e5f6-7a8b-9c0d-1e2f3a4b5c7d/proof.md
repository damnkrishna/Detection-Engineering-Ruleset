# Proof — a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c7d

## Rule

- **Rule ID:** a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c7d
- **Rule name:** Connection to Unlisted Public GenAI Services (AN2075-Unlisted-GenAI)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** []
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [reconnaissance] / [T1682]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `http_method` | http_method eq POST | `POST` |
| `destination_domain` | destination_domain contains chat AND destination_domain not_contains openai.com AND destination_domain not_contains chatgpt.com AND destination_domain not_contains claude.ai AND destination_domain not_contains gemini.google.com AND destination_domain not_contains cohere.com AND destination_domain not_contains poe.com | `cdn.example-updates.net chat` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `http_method`=POST<br>`destination_domain`=cdn.example-updates.net chat<br>`hostname`=HR-WKS-816<br>`agent_ip`=10.42.7.113<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.7.113`
- alert `dd42a7fdc5befaac63ad2f99c071bbbf` on lane `entity_key` = `10.42.7.113`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `http_method`=POST<br>`destination_domain`=C:\Windows\System32 ai-<br>`hostname`=FIN-WKS-815<br>`agent_ip`=10.42.6.113<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.6.113`
- alert `129aa5ea1e3308188fa6b059d5119a4e` on lane `entity_key` = `10.42.6.113`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'destination_domain not_contains poe.com' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `http_method`=POST<br>`destination_domain`=cdn.example-updates.net poe.com<br>`hostname`=HR-WKS-816<br>`agent_ip`=10.42.7.113<br>… | destination_domain=cdn.example-updates.net poe.com fails 'destination_domain not_contains poe.com' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.7.113`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'http_method eq POST' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `http_method`=POST.bak<br>`destination_domain`=cdn.example-updates.net chat<br>`hostname`=HR-WKS-816<br>`agent_ip`=10.42.7.113<br>… | http_method=POST.bak fails 'http_method eq POST' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.7.113`

