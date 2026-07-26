# Proof — AN0130

## Rule

- **Rule ID:** AN0130
- **Rule name:** Local Outlook Email Archive Access by Non-Outlook Process (AN0130)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [collection] / [T1114.001]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `file_path` | file_path regex .+\Q.pst\E$ | `C:\Users\j.mercer\AppData\Local\Temp\.pst` |
| `image_path` | image_path regex .+\Q\OUTLOOK.EXE\E$ AND image_path regex .+\Q\outlook.exe\E$ | `C:\Windows\System32\outlook.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\.pst<br>`image_path`=C:\Windows\System32\outlook.exe<br>`hostname`=HR-WKS-666<br>`agent_ip`=10.42.57.92<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.57.92`
- alert `d39336be07cc955622373b0a2702539e` on lane `entity_key` = `10.42.57.92`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp\Outlook F…<br>`image_path`=C:\Windows\System32\cmd.exe\outlook.exe<br>`hostname`=FIN-WKS-665<br>`agent_ip`=10.42.56.92<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.56.92`
- alert `335ca731a8106bbc95a637db0d27af71` on lane `entity_key` = `10.42.56.92`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .+\Q\outlook.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\.pst<br>`image_path`=C:\Windows\System32\outlook.exe.bak<br>`hostname`=HR-WKS-666<br>`agent_ip`=10.42.57.92<br>… | image_path=C:\Windows\System32\outlook.exe.bak fails 'image_path regex .+\Q\outlook.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.57.92`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'file_path regex .+\Q.pst\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\.pst.bak<br>`image_path`=C:\Windows\System32\outlook.exe<br>`hostname`=HR-WKS-666<br>`agent_ip`=10.42.57.92<br>… | file_path=C:\Users\j.mercer\AppData\Local\Temp\.pst.bak fails 'file_path regex .+\Q.pst\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.57.92`

