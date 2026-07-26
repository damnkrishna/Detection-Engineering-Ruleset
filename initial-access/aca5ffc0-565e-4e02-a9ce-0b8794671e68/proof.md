# Proof — aca5ffc0-565e-4e02-a9ce-0b8794671e68

## Rule

- **Rule ID:** aca5ffc0-565e-4e02-a9ce-0b8794671e68
- **Rule name:** Phishing - Suspicious File Attachment Written by Mail Client (AN0188-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [initial-access] / [T1566]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_path` | image_path regex .*\Q\outlook.exe\E$ | `C:\Windows\System32\outlook.exe` |
| `file_path` | file_path regex .*\Q.exe\E$ | `C:\Users\j.mercer\AppData\Local\Temp\.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\outlook.exe<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\.exe<br>`hostname`=HR-WKS-361<br>`agent_ip`=10.42.52.23<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.52.23`
- alert `59e1922e37f92565a61ce617d7f92df5` on lane `entity_key` = `10.42.52.23`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `image_path`=C:\Windows\System32\cmd.exe\thunderbird.exe<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp\.lnk<br>`hostname`=ENG-WKS-362<br>`agent_ip`=10.42.53.23<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.53.23`
- alert `8c6734e0c255e9673b969d70c325410d` on lane `entity_key` = `10.42.53.23`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'file_path regex .*\Q.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\outlook.exe<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\.exe.bak<br>`hostname`=HR-WKS-361<br>`agent_ip`=10.42.52.23<br>… | file_path=C:\Users\j.mercer\AppData\Local\Temp\.exe.bak fails 'file_path regex .*\Q.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.52.23`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\outlook.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\outlook.exe.bak<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\.exe<br>`hostname`=HR-WKS-361<br>`agent_ip`=10.42.52.23<br>… | image_path=C:\Windows\System32\outlook.exe.bak fails 'image_path regex .*\Q\outlook.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.52.23`

