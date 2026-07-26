# Proof — 8670912b-6848-44f4-9ee5-98442d5bb2e6

## Rule

- **Rule ID:** 8670912b-6848-44f4-9ee5-98442d5bb2e6
- **Rule name:** Lateral Movement - Deployment Agent Spawning Suspicious Shell (AN0623)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [lateral-movement] / [T1072]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `parent_image` | parent_image regex .*\Q\CcmExec.exe\E$ AND parent_image not_regex .*\Q\msiexec.exe\E$ AND parent_image not_regex .*\Q\setup.exe\E$ | `C:\Windows\CcmExec.exe` |
| `image_path` | image_path regex .*\Q\cmd.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `parent_image`=C:\Windows\CcmExec.exe<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=HR-WKS-451<br>`agent_ip`=10.42.42.110<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.42.110`
- alert `1c1fdca6490ce6b3b989dd8750bde584` on lane `entity_key` = `10.42.42.110`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `parent_image`=C:\Windows\explorer.exe\PDQDeployService.exe<br>`original_filename`=PowerShell.EXE<br>`hostname`=FIN-WKS-450<br>`agent_ip`=10.42.41.110<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.41.110`
- alert `684b48fd1cc0d98953bc2d91b22f9ae2` on lane `entity_key` = `10.42.41.110`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'parent_image not_regex .*\Q\setup.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `parent_image`=\setup.exe<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=HR-WKS-451<br>`agent_ip`=10.42.42.110<br>… | parent_image=\setup.exe fails 'parent_image not_regex .*\Q\setup.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.42.110`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\cmd.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `parent_image`=C:\Windows\CcmExec.exe<br>`image_path`=C:\Windows\System32\cmd.exe.bak<br>`hostname`=HR-WKS-451<br>`agent_ip`=10.42.42.110<br>… | image_path=C:\Windows\System32\cmd.exe.bak fails 'image_path regex .*\Q\cmd.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.42.110`

