# Proof — AN1604

## Rule

- **Rule ID:** AN1604
- **Rule name:** AN1604 - Generic Create Account
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [persistence] / [T1136]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `cmd_line` | cmd_line contains  user  AND cmd_line contains  /add | `"C:\Windows\System32\cmd.exe"  user  /add` |
| `image_path` | image_path regex .*\Q\net.exe\E$ | `C:\Windows\System32\net.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe"  user  /add<br>`image_path`=C:\Windows\System32\net.exe<br>`hostname`=SEC-WKS-839<br>`agent_ip`=10.42.30.86<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.30.86`
- alert `1f677ff936201aa9f35416dd52d005d7` on lane `entity_key` = `10.42.30.86`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe" /c whoami user  /add<br>`image_path`=C:\Windows\System32\cmd.exe\net1.exe<br>`hostname`=OPS-WKS-838<br>`agent_ip`=10.42.29.86<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.29.86`
- alert `5592733633d7a719a9a747a63c04242d` on lane `entity_key` = `10.42.29.86`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\net.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe"  user  /add<br>`image_path`=C:\Windows\System32\net.exe.bak<br>`hostname`=SEC-WKS-839<br>`agent_ip`=10.42.30.86<br>… | image_path=C:\Windows\System32\net.exe.bak fails 'image_path regex .*\Q\net.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.30.86`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains  /add' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe"  user  /contoso-add<br>`image_path`=C:\Windows\System32\net.exe<br>`hostname`=SEC-WKS-839<br>`agent_ip`=10.42.30.86<br>… | cmd_line="C:\Windows\System32\cmd.exe"  user  /contoso-add fails 'cmd_line contains  /add' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.30.86`

