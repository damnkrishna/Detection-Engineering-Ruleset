# Proof — f48b1112-9844-4632-901b-c1284a14f4e8

## Rule

- **Rule ID:** f48b1112-9844-4632-901b-c1284a14f4e8
- **Rule name:** Suspicious Execution via Malicious Installer/Package Manager (AN0699)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [execution] / [T1204.005]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `parent_image` | parent_image regex .*\Q\pip.exe\E$ | `C:\Windows\pip.exe` |
| `image_path` | image_path regex .*\Q\python.exe\E$ | `C:\Windows\System32\python.exe` |
| `cmd_line` | cmd_line contains install | `"C:\Windows\System32\cmd.exe" install` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `parent_image`=C:\Windows\pip.exe<br>`image_path`=C:\Windows\System32\python.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" install<br>`hostname`=HR-WKS-051<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.142.61`
- alert `5076a4d32379482f90c185f11e25d101` on lane `entity_key` = `10.42.142.61`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `parent_image`=C:\Windows\explorer.exe\npm.cmd<br>`image_path`=C:\Windows\System32\cmd.exe\node.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami setup.py<br>`hostname`=ENG-WKS-052<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.143.61`
- alert `ab68af6b999a0762cbbf7f7860f169f6` on lane `entity_key` = `10.42.143.61`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains install' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `parent_image`=C:\Windows\pip.exe<br>`image_path`=C:\Windows\System32\python.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>`hostname`=HR-WKS-051<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami fails 'cmd_line contains install' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.142.61`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\python.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `parent_image`=C:\Windows\pip.exe<br>`image_path`=C:\Windows\System32\python.exe.bak<br>`cmd_line`="C:\Windows\System32\cmd.exe" install<br>`hostname`=HR-WKS-051<br>… | image_path=C:\Windows\System32\python.exe.bak fails 'image_path regex .*\Q\python.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.142.61`

