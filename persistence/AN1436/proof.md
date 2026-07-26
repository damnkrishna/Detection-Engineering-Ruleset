# Proof — AN1436

## Rule

- **Rule ID:** AN1436
- **Rule name:** AN1436 - Office Application Startup: Office Template Macros
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [persistence] / [T1137.001]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `registry_event_type` | registry_event_type eq CreateFile | `CreateFile` |
| `file_path` | file_path regex .*\Q\Microsoft\Templates\Normal.dotm\E$ | `C:\Users\j.mercer\AppData\Local\Temp\Microsoft\Templates\Normal.dotm` |
| `image_path` | image_path not_regex .*\Q\winword.exe\E$ AND image_path not_regex .*\Q\excel.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `registry_event_type`=CreateFile<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\Microsoft\Templates\…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=HR-WKS-686<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.177.64`
- alert `7ec7ebb05c525cea088a8c07f9c1f615` on lane `entity_key` = `10.42.177.64`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `registry_event_type`=CreateFile<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp\Microsoft…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-685<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.176.64`
- alert `5e0b51d73c0784c0299bfd70959bb790` on lane `entity_key` = `10.42.176.64`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\excel.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `registry_event_type`=CreateFile<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\Microsoft\Templates\…<br>`image_path`=\excel.exe<br>`hostname`=HR-WKS-686<br>… | image_path=\excel.exe fails 'image_path not_regex .*\Q\excel.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.177.64`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'file_path regex .*\Q\Microsoft\Templates\Normal.dotm\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `registry_event_type`=CreateFile<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\Microsoft\Templates\…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=HR-WKS-686<br>… | file_path=C:\Users\j.mercer\AppData\Local\Temp\Microsoft\Templates\Normal.dotm.bak fails 'file_path regex .*\Q\Microsoft\Templates\Normal.dotm\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.177.64`

