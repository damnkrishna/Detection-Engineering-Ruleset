# Proof — AN0577

## Rule

- **Rule ID:** AN0577
- **Rule name:** Execution of Legitimate Binary from Suspicious Directory (AN0577)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [execution, persistence, privilege-escalation] / [T1574.001]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_path` | image_path regex .+\Q\calc.exe\E$ | `C:\Windows\System32\calc.exe` |
| `cmd_line` | cmd_line contains \AppData\Local\Temp\ AND cmd_line contains C:\Windows\System32\ AND cmd_line contains C:\Windows\SysWOW64\ AND cmd_line contains C:\Windows\ | `"C:\Windows\System32\cmd.exe" \AppData\Local\Temp\C:\Windows\SysWOW64\` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\calc.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" \AppData\Local\Temp\C:\Wind…<br>`hostname`=HR-WKS-291<br>`agent_ip`=10.42.82.192<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.82.192`
- alert `a4ce05d5d830d89316a031e9a3d60423` on lane `entity_key` = `10.42.82.192`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `original_filename`=NOTEPAD.EXE<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami\Users\Public\C:\W…<br>`hostname`=FIN-WKS-290<br>`agent_ip`=10.42.81.192<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.81.192`
- alert `755114a9ff0fff04bcc0e7623f815e6e` on lane `entity_key` = `10.42.81.192`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains C:\Windows\' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\calc.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>`hostname`=HR-WKS-291<br>`agent_ip`=10.42.82.192<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami fails 'cmd_line contains C:\Windows\' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.82.192`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .+\Q\calc.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\calc.exe.bak<br>`cmd_line`="C:\Windows\System32\cmd.exe" \AppData\Local\Temp\C:\Wind…<br>`hostname`=HR-WKS-291<br>`agent_ip`=10.42.82.192<br>… | image_path=C:\Windows\System32\calc.exe.bak fails 'image_path regex .+\Q\calc.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.82.192`

