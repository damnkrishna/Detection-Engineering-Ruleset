# Proof — AN0975

## Rule

- **Rule ID:** AN0975
- **Rule name:** Abuse of UAC Elevation Control Mechanisms (AN0975)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [privilege-escalation, defense-evasion] / [T1548]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `cmd_line` | cmd_line contains \Software\Classes\mscfile\shell\open\command AND cmd_line contains add | `"C:\Windows\System32\cmd.exe" /c whoami\Software\Classes\mscfile\shell\open\command add` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe" /c whoami\Software\Classes\…<br>`hostname`=OPS-WKS-828<br>`agent_ip`=10.42.119.131<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; operates on a staging-directory path, which is what marks the process suspicious and backs the rule's high-rarity ATT&CK claim [T1548] |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.119.131`
- alert `b87880576877d891a46e75da57278044` on lane `entity_key` = `10.42.119.131`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T12:00:00.000Z | 0 | `cmd_line`=C:\Users\j.mercer\AppData\Local\Temp\Software\Classes\ms-…<br>`hostname`=HR-WKS-826<br>`agent_ip`=10.42.117.131<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.117.131`
- alert `1a39edd42a696c03dbc4bd3a36a2e943` on lane `entity_key` = `10.42.117.131`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .+\Q\cmd.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `parent_image`=C:\Windows\control.exe<br>`image_path`=C:\Windows\System32\cmd.exe.bak<br>`hostname`=SEC-WKS-829<br>`agent_ip`=10.42.120.131<br>… | image_path=C:\Windows\System32\cmd.exe.bak fails 'image_path regex .+\Q\cmd.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.120.131`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'parent_image regex .+\Q\control.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `parent_image`=C:\Windows\control.exe.bak<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=SEC-WKS-829<br>`agent_ip`=10.42.120.131<br>… | parent_image=C:\Windows\control.exe.bak fails 'parent_image regex .+\Q\control.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.120.131`

