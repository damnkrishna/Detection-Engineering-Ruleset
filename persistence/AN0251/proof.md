# Proof — AN0251

## Rule

- **Rule ID:** AN0251
- **Rule name:** AN0251 - Generic Software Extensions
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [persistence] / [T1176]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `cmd_line` | cmd_line contains install-extension | `"C:\Windows\System32\cmd.exe" install-extension` |
| `image_path` | image_path regex .*\Q\cmd.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe" install-extension<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=ENG-WKS-302<br>`agent_ip`=10.42.193.171<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.193.171`
- alert `50636577b687ce41ac94b0f5797644df` on lane `entity_key` = `10.42.193.171`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe" /c whoami install-extension<br>`image_path`=C:\Windows\System32\cmd.exe\powershell.exe<br>`hostname`=HR-WKS-301<br>`agent_ip`=10.42.192.171<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.192.171`
- alert `033da3a43e895185e9c5cc68d65cb5b1` on lane `entity_key` = `10.42.192.171`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\cmd.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe" install-extension<br>`image_path`=C:\Windows\System32\cmd.exe.bak<br>`hostname`=ENG-WKS-302<br>`agent_ip`=10.42.193.171<br>… | image_path=C:\Windows\System32\cmd.exe.bak fails 'image_path regex .*\Q\cmd.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.193.171`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains install-extension' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=ENG-WKS-302<br>`agent_ip`=10.42.193.171<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami fails 'cmd_line contains install-extension' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.193.171`

