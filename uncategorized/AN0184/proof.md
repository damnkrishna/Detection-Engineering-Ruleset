# Proof — AN0184

## Rule

- **Rule ID:** AN0184
- **Rule name:** Malicious IIS Module or ISAPI Filter Installation (AN0184)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [persistence] / [T1505.004]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_path` | image_path regex .+\Q\appcmd.exe\E$ | `C:\Windows\System32\appcmd.exe` |
| `cmd_line` | cmd_line contains  install  | `"C:\Windows\System32\cmd.exe"  install C:\Users\Public\export.dat` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\appcmd.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe"  install C:\Users\Public\ex…<br>`hostname`=ENG-WKS-867<br>`agent_ip`=10.42.58.128<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.58.128`
- alert `c790d2ebacf964340356d43bf9fd2a2d` on lane `entity_key` = `10.42.58.128`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `original_filename`=pwsh.dll<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami Add-WebConfiguration<br>`hostname`=HR-WKS-866<br>`agent_ip`=10.42.57.128<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.57.128`
- alert `04ec016810c4df2aa9e6ffffa4abf58f` on lane `entity_key` = `10.42.57.128`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains  install ' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\appcmd.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>`hostname`=ENG-WKS-867<br>`agent_ip`=10.42.58.128<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami fails 'cmd_line contains  install ' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.58.128`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .+\Q\appcmd.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\appcmd.exe.bak<br>`cmd_line`="C:\Windows\System32\cmd.exe"  install C:\Users\Public\ex…<br>`hostname`=ENG-WKS-867<br>`agent_ip`=10.42.58.128<br>… | image_path=C:\Windows\System32\appcmd.exe.bak fails 'image_path regex .+\Q\appcmd.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.58.128`

