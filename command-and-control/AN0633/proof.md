# Proof — AN0633

## Rule

- **Rule ID:** AN0633
- **Rule name:** Outbound Network Connection via Non-Standard Port (AN0633)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [command-and-control] / [T1571]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `dst_port` | dst_port in_list [4444, 4445, 5555, 8000, 8080, 8443, 8888, 9001, 9999] | `4444` |
| `image_path` | image_path regex .+\Q\cmd.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `dst_port`=4444<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=OPS-WKS-778<br>`agent_ip`=10.42.169.189<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.169.189`
- alert `9ebe45a67a0c73ede53ef6967ae11a7f` on lane `entity_key` = `10.42.169.189`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `dst_port`=4445<br>`image_path`=C:\Windows\System32\cmd.exe\powershell.exe<br>`hostname`=ENG-WKS-777<br>`agent_ip`=10.42.168.189<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.168.189`
- alert `1b9af232387adefeb4246dbeb5167e88` on lane `entity_key` = `10.42.168.189`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .+\Q\cmd.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `dst_port`=4444<br>`image_path`=C:\Windows\System32\cmd.exe.bak<br>`hostname`=OPS-WKS-778<br>`agent_ip`=10.42.169.189<br>… | image_path=C:\Windows\System32\cmd.exe.bak fails 'image_path regex .+\Q\cmd.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.169.189`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'dst_port in_list [4444, 4445, 5555, 8000, 8080, 8443, 8888, 9001, 9999]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `dst_port`=4444.bak<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=OPS-WKS-778<br>`agent_ip`=10.42.169.189<br>… | dst_port=4444.bak fails 'dst_port in_list [4444, 4445, 5555, 8000, 8080, 8443, 8888, 9001, 9999]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.169.189`

