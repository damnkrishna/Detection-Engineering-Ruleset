# Proof — AN0137

## Rule

- **Rule ID:** AN0137
- **Rule name:** Malicious Office Add-in Drop for Persistence (AN0137)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [persistence] / [T1137.006]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `file_path` | file_path contains \Microsoft\Word\Startup\ | `C:\Users\j.mercer\AppData\Local\Temp\Microsoft\Word\Startup\` |
| `image_path` | image_path contains \OfficeClickToRun.exe AND image_path contains \OfficeC2RClient.exe AND image_path contains \setup.exe | `C:\Windows\System32\OfficeClickToRun.exe\OfficeC2RClient.exe\setup.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\Microsoft\Word\Startup\<br>`image_path`=C:\Windows\System32\OfficeClickToRun.exe\OfficeC2RClient.…<br>`hostname`=SEC-WKS-239<br>`agent_ip`=10.42.130.58<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.130.58`
- alert `9060515a487d51ff2405a60981b09839` on lane `entity_key` = `10.42.130.58`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp\.xll<br>`image_path`=C:\Windows\System32\cmd.exe\OfficeClickToRun.exe\OfficeC2…<br>`hostname`=OPS-WKS-238<br>`agent_ip`=10.42.129.58<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.129.58`
- alert `2c8bc28e04a147ca91970b798751f049` on lane `entity_key` = `10.42.129.58`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path contains \setup.exe' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\Microsoft\Word\Startup\<br>`image_path`=C:\Windows\System32\OfficeClickToRun_helper.exe\OfficeC2R…<br>`hostname`=SEC-WKS-239<br>`agent_ip`=10.42.130.58<br>… | image_path=C:\Windows\System32\OfficeClickToRun_helper.exe\OfficeC2RClient_helper.exe\setup_helper.exe fails 'image_path contains \setup.exe' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.130.58`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'file_path contains \Microsoft\Word\Startup\' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp<br>`image_path`=C:\Windows\System32\OfficeClickToRun.exe\OfficeC2RClient.…<br>`hostname`=SEC-WKS-239<br>`agent_ip`=10.42.130.58<br>… | file_path=C:\Users\j.mercer\AppData\Local\Temp\report.tmp fails 'file_path contains \Microsoft\Word\Startup\' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.130.58`

