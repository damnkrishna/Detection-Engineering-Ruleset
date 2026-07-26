# Proof — a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d

## Rule

- **Rule ID:** a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d
- **Rule name:** Outbound Data Upload to Public GenAI Services (AN2075)
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
| `bytes_sent` | bytes_sent gte 10000 | `10000` |
| `destination_domain` | destination_domain contains openai.com | `cdn.example-updates.net openai.com` |
| `src_ip` | src_ip not_in_cidr 10.100.200.0/24 | `10.42.7.14` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `http_method`=POST<br>`bytes_sent`=10000<br>`destination_domain`=cdn.example-updates.net openai.com<br>`src_ip`=10.42.7.14<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 2 (1 cross-lane twin pair(s) merged by the post-correlation chain)
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.198.61`
- alert `50e1956337b4706568a89efbfa3aeb50` on lane `entity_key` = `10.42.198.61`, match mode `THRESHOLD`, 1 matched event(s)
- alert `6d3786435141f6c9de62d1816a1a0b66` on lane `src_ip` = `10.42.7.14`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `http_method`=POST<br>`bytes_sent`=10000<br>`destination_domain`=C:\Windows\System32 chatgpt.com<br>`username`=CORP\j.mercer<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `CORP\j.mercer`
- alert `fc1fa09cb2eadcf90fc301f745d8129d` on lane `entity_key` = `CORP\j.mercer`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'destination_domain contains openai.com' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `http_method`=POST<br>`bytes_sent`=10000<br>`destination_domain`=cdn.example-updates.net<br>`src_ip`=10.42.7.14<br>… | destination_domain=cdn.example-updates.net fails 'destination_domain contains openai.com' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.198.61`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'bytes_sent gte 10000' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `http_method`=POST<br>`bytes_sent`=10000.bak<br>`destination_domain`=cdn.example-updates.net openai.com<br>`src_ip`=10.42.7.14<br>… | bytes_sent=10000.bak fails 'bytes_sent gte 10000' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.198.61`

