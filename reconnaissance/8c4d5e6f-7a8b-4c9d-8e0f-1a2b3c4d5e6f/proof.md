# Proof — 8c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f

## Rule

- **Rule ID:** 8c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f
- **Rule name:** Access to Deprecated or Historical Endpoint Patterns (AN2069-Historical-Paths)
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
| `http_request_path` | http_request_path regex .*\/v[0-9]+\/.* | `/v0/` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `http_request_path`=/v0/<br>`hostname`=FIN-WKS-515<br>`agent_ip`=10.42.6.72<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.6.72`
- alert `09f3bfb389fc4dab706edaedb8edcb7e` on lane `entity_key` = `10.42.6.72`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `http_request_path`=/api/v0/<br>`hostname`=SEC-WKS-514<br>`agent_ip`=10.42.5.72<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.5.72`
- alert `a4263a28b41c9857cbd91e3f91545190` on lane `entity_key` = `10.42.5.72`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'http_request_path regex .*\/v[0-9]+\/.*' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `http_request_path`=C:\Program Files\Contoso\Reporting\contoso-report.exe<br>`hostname`=FIN-WKS-515<br>`agent_ip`=10.42.6.72<br>`event_id`=1<br>… | http_request_path=C:\Program Files\Contoso\Reporting\contoso-report.exe fails 'http_request_path regex .*\/v[0-9]+\/.*' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.6.72`

## benign_2

**Expected alerts:** 0  
**Construction:** the field 'http_request_path' is absent entirely; an absent field is no-match for every operator, so the stage is never entered

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `hostname`=FIN-WKS-515<br>`agent_ip`=10.42.6.72<br>`event_id`=1<br>`image_path`=C:\Windows\System32\cmd.exe<br>… | carries no 'http_request_path' at all; evaluateCondition returns no-match for every operator on an absent field, so the stage gate rejects the event |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.6.72`

