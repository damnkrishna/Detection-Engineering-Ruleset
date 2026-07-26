# Proof — AN0834

## Rule

- **Rule ID:** AN0834
- **Rule name:** Suspicious File and Directory Permissions Modification (AN0834)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [defense-evasion, privilege-escalation] / [T1222.001]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `cmd_line` | cmd_line contains  /f  AND cmd_line contains  /r | `"C:\Windows\System32\cmd.exe"  /f  /r` |
| `image_path` | image_path regex .+\Q\takeown.exe\E$ | `C:\Windows\System32\takeown.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe"  /f  /r<br>`image_path`=C:\Windows\System32\takeown.exe<br>`hostname`=FIN-WKS-475<br>`agent_ip`=10.42.166.149<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.166.149`
- alert `5574d1476ada6156d1c54140769b7d5f` on lane `entity_key` = `10.42.166.149`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `original_filename`=cacls.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami Everyone:FA<br>`hostname`=SEC-WKS-474<br>`agent_ip`=10.42.165.149<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.165.149`
- alert `b828e9c59f0ee67d19172a05b7c4cc71` on lane `entity_key` = `10.42.165.149`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .+\Q\takeown.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe"  /f  /r<br>`image_path`=C:\Windows\System32\takeown.exe.bak<br>`hostname`=FIN-WKS-475<br>`agent_ip`=10.42.166.149<br>… | image_path=C:\Windows\System32\takeown.exe.bak fails 'image_path regex .+\Q\takeown.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.166.149`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains  /r' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe"  /f  /contoso-r<br>`image_path`=C:\Windows\System32\takeown.exe<br>`hostname`=FIN-WKS-475<br>`agent_ip`=10.42.166.149<br>… | cmd_line="C:\Windows\System32\cmd.exe"  /f  /contoso-r fails 'cmd_line contains  /r' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.166.149`

