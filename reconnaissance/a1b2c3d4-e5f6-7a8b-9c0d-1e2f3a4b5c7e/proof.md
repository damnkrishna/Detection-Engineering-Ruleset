# Proof — a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c7e

## Rule

- **Rule ID:** a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c7e
- **Rule name:** Outbound Secret Leakage to GenAI Services via Decrypted SSL (AN2075-Decrypted-Leaking)
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
| `destination_domain` | destination_domain contains openai.com | `cdn.example-updates.net openai.com` |
| `request_body` | request_body regex (?i)BEGIN (RSA\|EC\|PRIVATE) KEY | `BEGIN RSA KEY` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `destination_domain`=cdn.example-updates.net openai.com<br>`request_body`=BEGIN RSA KEY<br>`hostname`=FIN-WKS-755<br>`agent_ip`=10.42.46.108<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.46.108`
- alert `43ecade07b92ec4829887daf00a425dc` on lane `entity_key` = `10.42.46.108`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `destination_domain`=C:\Windows\System32 chatgpt.com<br>`request_body`=password=<br>`hostname`=SEC-WKS-754<br>`agent_ip`=10.42.45.108<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.45.108`
- alert `5850921066fb08c953d8773ea6be0cec` on lane `entity_key` = `10.42.45.108`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'request_body regex (?i)BEGIN (RSA\|EC\|PRIVATE) KEY' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `destination_domain`=cdn.example-updates.net openai.com<br>`request_body`=action=status&id=1<br>`hostname`=FIN-WKS-755<br>`agent_ip`=10.42.46.108<br>… | request_body=action=status&id=1 fails 'request_body regex (?i)BEGIN (RSA\|EC\|PRIVATE) KEY' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.46.108`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'destination_domain contains openai.com' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `destination_domain`=cdn.example-updates.net<br>`request_body`=BEGIN RSA KEY<br>`hostname`=FIN-WKS-755<br>`agent_ip`=10.42.46.108<br>… | destination_domain=cdn.example-updates.net fails 'destination_domain contains openai.com' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.46.108`

