# Proof — cd3de85d-e999-4e52-a4ff-031b978794d8

## Rule

- **Rule ID:** cd3de85d-e999-4e52-a4ff-031b978794d8
- **Rule name:** Keyboard Layout Registry Tampering (AN0243-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [collection] / [T1056.001]
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
| `target_object` | target_object contains SYSTEM\CurrentControlSet\Control\Keyboard Layout AND target_object regex .*\Q\Scancode Map\E$ | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run SYSTEM\CurrentControlSet\Control\Keyboard Layout\Scancode Map` |
| `image_path` | image_path not_regex .*\Q\ctfmon.exe\E$ AND image_path not_regex .*\Q\explorer.exe\E$ AND image_path not_regex .*\Q\svchost.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run SYSTEM…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=ENG-WKS-482<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.73.54`
- alert `fb8bc37df0cda6d527beca59e93ca239` on lane `entity_key` = `10.42.73.54`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDri…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=OPS-WKS-483<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.74.54`
- alert `18f796b22ce9cf4840db562acef51d9b` on lane `entity_key` = `10.42.74.54`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\svchost.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run SYSTEM…<br>`image_path`=\svchost.exe<br>`hostname`=ENG-WKS-482<br>… | image_path=\svchost.exe fails 'image_path not_regex .*\Q\svchost.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.73.54`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_object regex .*\Q\Scancode Map\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run SYSTEM…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=ENG-WKS-482<br>… | target_object=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run SYSTEM\CurrentControlSet\Control\Keyboard Layout\Scancode Map.bak fails 'target_object regex .*\Q\Scancode Map\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.73.54`

