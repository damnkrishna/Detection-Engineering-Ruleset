# Proof — cf7c3216-ea2c-4e2b-ac64-2935d5b45f65

## Rule

- **Rule ID:** cf7c3216-ea2c-4e2b-ac64-2935d5b45f65
- **Rule name:** System Owner and User Discovery via PowerShell Script Block (AN0254-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [discovery] / [T1033]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `script_block_text` | script_block_text contains Get-LocalUser | `Get-Process \| Select-Object Name, Id Get-LocalUser` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `script_block_text`=Get-Process \| Select-Object Name, Id Get-LocalUser<br>`hostname`=SEC-WKS-014<br>`agent_ip`=10.42.105.59<br>`event_id`=4104<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.105.59`
- alert `f25fa670fdd606c3fe29535514ca5252` on lane `entity_key` = `10.42.105.59`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `script_block_text`=C:\Windows\System32 Get-ADUser<br>`hostname`=OPS-WKS-013<br>`agent_ip`=10.42.104.59<br>`event_id`=4104<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.104.59`
- alert `7d8521c7e7e9257f7c082c74dfd9134f` on lane `entity_key` = `10.42.104.59`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'script_block_text contains Get-LocalUser' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `script_block_text`=Get-Process \| Select-Object Name, Id<br>`hostname`=SEC-WKS-014<br>`agent_ip`=10.42.105.59<br>`event_id`=4104<br>… | script_block_text=Get-Process \| Select-Object Name, Id fails 'script_block_text contains Get-LocalUser' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.105.59`

## benign_2

**Expected alerts:** 0  
**Construction:** the field 'script_block_text' is absent entirely; an absent field is no-match for every operator, so the stage is never entered

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `hostname`=SEC-WKS-014<br>`agent_ip`=10.42.105.59<br>`event_id`=4104<br>`image_path`=C:\Windows\System32\cmd.exe<br>… | carries no 'script_block_text' at all; evaluateCondition returns no-match for every operator on an absent field, so the stage gate rejects the event |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.105.59`

