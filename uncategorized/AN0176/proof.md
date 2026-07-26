# Proof — AN0176

## Rule

- **Rule ID:** AN0176
- **Rule name:** Creation of Service with Unquoted Binary Path via CLI (AN0176)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [execution, persistence, privilege-escalation] / [T1574.009]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_path` | image_path regex .+\Q\sc.exe\E$ | `C:\Windows\System32\sc.exe` |
| `cmd_line` | cmd_line contains create AND cmd_line contains binpath= AND cmd_line contains Program Files AND cmd_line contains \" AND cmd_line contains "" AND cmd_line contains `" AND cmd_line contains \"" | `"C:\Windows\System32\cmd.exe" create binpath=Program Files\" "" `"\""` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\sc.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" create binpath=Program File…<br>`hostname`=HR-WKS-836<br>`agent_ip`=10.42.127.67<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.127.67`
- alert `8819fd2e70b9780ba5978f2d15a041f1` on lane `entity_key` = `10.42.127.67`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `original_filename`=sc.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami config binPath=Do…<br>`hostname`=FIN-WKS-835<br>`agent_ip`=10.42.126.67<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.126.67`
- alert `99ff806b6ce493ed696843d7eb99a8b7` on lane `entity_key` = `10.42.126.67`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains \""' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\sc.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" create binpath=Program File…<br>`hostname`=HR-WKS-836<br>`agent_ip`=10.42.127.67<br>… | cmd_line="C:\Windows\System32\cmd.exe" create binpath=Program Files\" "" `"\contoso-"" fails 'cmd_line contains \""' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.127.67`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .+\Q\sc.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\sc.exe.bak<br>`cmd_line`="C:\Windows\System32\cmd.exe" create binpath=Program File…<br>`hostname`=HR-WKS-836<br>`agent_ip`=10.42.127.67<br>… | image_path=C:\Windows\System32\sc.exe.bak fails 'image_path regex .+\Q\sc.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.127.67`

