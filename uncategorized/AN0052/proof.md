# Proof — AN0052

## Rule

- **Rule ID:** AN0052
- **Rule name:** Loading of Suspicious DLL from User-Writable Directory (AN0052)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [execution] / [T1129]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_signed` | image_signed eq false | `false` |
| `image_loaded` | image_loaded contains \AppData\Local\Temp\ | `C:\Windows\System32\AppData\Local\Temp\` |
| `image_path` | image_path regex .+\Q\explorer.exe\E$ | `C:\Windows\System32\explorer.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_signed`=false<br>`image_loaded`=C:\Windows\System32\AppData\Local\Temp\<br>`image_path`=C:\Windows\System32\explorer.exe<br>`hostname`=OPS-WKS-483<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.74.202`
- alert `b2557e37491a378a6e25585318e8e8b8` on lane `entity_key` = `10.42.74.202`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `image_signed`=false<br>`image_loaded`=C:\Windows\System32\amsi.dll\Users\Public\<br>`image_path`=C:\Windows\System32\cmd.exe\svchost.exe<br>`hostname`=ENG-WKS-482<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.73.202`
- alert `3db2d974d9f199244c4bcb0687be2776` on lane `entity_key` = `10.42.73.202`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .+\Q\explorer.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_signed`=false<br>`image_loaded`=C:\Windows\System32\AppData\Local\Temp\<br>`image_path`=C:\Windows\System32\explorer.exe.bak<br>`hostname`=OPS-WKS-483<br>… | image_path=C:\Windows\System32\explorer.exe.bak fails 'image_path regex .+\Q\explorer.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.74.202`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_loaded contains \AppData\Local\Temp\' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_signed`=false<br>`image_loaded`=C:\Windows\System32\amsi.dll<br>`image_path`=C:\Windows\System32\explorer.exe<br>`hostname`=OPS-WKS-483<br>… | image_loaded=C:\Windows\System32\amsi.dll fails 'image_loaded contains \AppData\Local\Temp\' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.74.202`

