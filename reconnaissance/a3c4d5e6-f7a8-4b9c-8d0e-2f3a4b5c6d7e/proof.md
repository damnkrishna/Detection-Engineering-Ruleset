# Proof — a3c4d5e6-f7a8-4b9c-8d0e-2f3a4b5c6d7e

## Rule

- **Rule ID:** a3c4d5e6-f7a8-4b9c-8d0e-2f3a4b5c6d7e
- **Rule name:** Web Fuzzing Tool User-Agent Detection (AN2069-Fuzzing-Agents)
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
| `user_agent` | user_agent contains ffuf/ | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit ffuf/` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `user_agent`=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit ffuf/<br>`hostname`=HR-WKS-861<br>`agent_ip`=10.42.52.11<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.52.11`
- alert `d12b1b503882adb98e1084efb342c8bd` on lane `entity_key` = `10.42.52.11`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `user_agent`=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537…<br>`hostname`=ENG-WKS-862<br>`agent_ip`=10.42.53.11<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.53.11`
- alert `6ce9454e367a5737a29446fdcfcf32e7` on lane `entity_key` = `10.42.53.11`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'user_agent contains ffuf/' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `user_agent`=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36<br>`hostname`=HR-WKS-861<br>`agent_ip`=10.42.52.11<br>`event_id`=1<br>… | user_agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 fails 'user_agent contains ffuf/' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.52.11`

## benign_2

**Expected alerts:** 0  
**Construction:** the field 'user_agent' is absent entirely; an absent field is no-match for every operator, so the stage is never entered

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `hostname`=HR-WKS-861<br>`agent_ip`=10.42.52.11<br>`event_id`=1<br>`image_path`=C:\Windows\System32\cmd.exe<br>… | carries no 'user_agent' at all; evaluateCondition returns no-match for every operator on an absent field, so the stage gate rejects the event |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.52.11`

