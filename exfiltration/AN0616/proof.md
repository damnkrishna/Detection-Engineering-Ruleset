# Proof — AN0616

## Rule

- **Rule ID:** AN0616
- **Rule name:** File Copy to USB Storage via CLI (AN0616)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [exfiltration] / [T1052.001]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_path` | image_path regex .+\Q\xcopy.exe\E$ | `C:\Windows\System32\xcopy.exe` |
| `file_path` | file_path starts_with D:\ | `D:\` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\xcopy.exe<br>`file_path`=D:\<br>`hostname`=ENG-WKS-777<br>`agent_ip`=10.42.68.73<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.68.73`
- alert `7142c003618ba3d3c2059f6ff2523a3a` on lane `entity_key` = `10.42.68.73`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `image_path`=C:\Windows\System32\cmd.exe\robocopy.exe<br>`file_path`=E:\<br>`hostname`=HR-WKS-776<br>`agent_ip`=10.42.67.73<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.67.73`
- alert `367cb444827b76e091282f9521e7f06e` on lane `entity_key` = `10.42.67.73`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'file_path starts_with D:\' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\xcopy.exe<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp<br>`hostname`=ENG-WKS-777<br>`agent_ip`=10.42.68.73<br>… | file_path=C:\Users\j.mercer\AppData\Local\Temp\report.tmp fails 'file_path starts_with D:\' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.68.73`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .+\Q\xcopy.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\xcopy.exe.bak<br>`file_path`=D:\<br>`hostname`=ENG-WKS-777<br>`agent_ip`=10.42.68.73<br>… | image_path=C:\Windows\System32\xcopy.exe.bak fails 'image_path regex .+\Q\xcopy.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.68.73`

