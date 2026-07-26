# Proof — AN0105

## Rule

- **Rule ID:** AN0105
- **Rule name:** Suspicious Browser Credential Store Access (AN0105)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [credential-access] / [T1555.003]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_path` | image_path regex .+\Q\cmd.exe\E$ | `C:\Windows\System32\cmd.exe` |
| `cmd_line` | cmd_line contains \Google\Chrome\User Data\*\Login Data | `"C:\Windows\System32\cmd.exe" \Google\Chrome\User Data\*\Login Data` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\cmd.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" \Google\Chrome\User Data\*\…<br>`hostname`=SEC-WKS-634<br>`agent_ip`=10.42.25.115<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.25.115`
- alert `00a80c6892f4e01b9df2536a9bda2033` on lane `entity_key` = `10.42.25.115`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `image_path`=C:\Windows\System32\cmd.exe\powershell.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami key4.db<br>`hostname`=OPS-WKS-633<br>`agent_ip`=10.42.24.115<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.24.115`
- alert `23a558f25943b0e71b754a30ed37ccc5` on lane `entity_key` = `10.42.24.115`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains \Google\Chrome\User Data\*\Login Data' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\cmd.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" \Google\Chrome\User Data\*\…<br>`hostname`=SEC-WKS-634<br>`agent_ip`=10.42.25.115<br>… | cmd_line="C:\Windows\System32\cmd.exe" \Google\Chrome\User Data\*\contoso-Login Data fails 'cmd_line contains \Google\Chrome\User Data\*\Login Data' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.25.115`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .+\Q\cmd.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\cmd.exe.bak<br>`cmd_line`="C:\Windows\System32\cmd.exe" \Google\Chrome\User Data\*\…<br>`hostname`=SEC-WKS-634<br>`agent_ip`=10.42.25.115<br>… | image_path=C:\Windows\System32\cmd.exe.bak fails 'image_path regex .+\Q\cmd.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.25.115`

