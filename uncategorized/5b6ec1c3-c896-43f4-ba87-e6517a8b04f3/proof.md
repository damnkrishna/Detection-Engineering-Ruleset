# Proof — 5b6ec1c3-c896-43f4-ba87-e6517a8b04f3

## Rule

- **Rule ID:** 5b6ec1c3-c896-43f4-ba87-e6517a8b04f3
- **Rule name:** MFA Registry Configuration Tampering (AN0543-A)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [] / [T1556.006]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id eq 13 | `13` |
| `registry_new_value` | registry_new_value eq DWORD (0x00000000) | `DWORD (0x00000000)` |
| `target_object` | target_object contains \Microsoft\Windows\System\PINLogin | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Microsoft\Windows\System\PINLogin` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`registry_new_value`=DWORD (0x00000000)<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Micros…<br>`hostname`=OPS-WKS-188<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.179.209`
- alert `b5b36f1a6c9fc606ad40562fa14fab80` on lane `entity_key` = `10.42.179.209`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDri…<br>`registry_new_value`=DWORD (0x00000001)<br>`hostname`=ENG-WKS-187<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.178.209`
- alert `dfd32af5e8f63f11c306e2a9e358a6b6` on lane `entity_key` = `10.42.178.209`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_object contains \Microsoft\Windows\System\PINLogin' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`registry_new_value`=DWORD (0x00000000)<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Micros…<br>`hostname`=OPS-WKS-188<br>… | target_object=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Microsoft\Windows\System\contoso-PINLogin fails 'target_object contains \Microsoft\Windows\System\PINLogin' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.179.209`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'registry_new_value eq DWORD (0x00000000)' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`registry_new_value`=DWORD (0x00000000).bak<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Micros…<br>`hostname`=OPS-WKS-188<br>… | registry_new_value=DWORD (0x00000000).bak fails 'registry_new_value eq DWORD (0x00000000)' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.179.209`

