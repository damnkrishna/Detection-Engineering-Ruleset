# Proof — 50f3bf00-e552-4dab-a402-9b891308bc44

## Rule

- **Rule ID:** 50f3bf00-e552-4dab-a402-9b891308bc44
- **Rule name:** Supply Chain Tampering - Suspicious Process Spawned by Development Tool via CLI (AN0021-A)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [initial-access] / [T1195.001]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `parent_image` | parent_image regex .*\Q\node.exe\E$ | `C:\Windows\node.exe` |
| `image_path` | image_path regex .*\Q\cmd.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `parent_image`=C:\Windows\node.exe<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-115<br>`agent_ip`=10.42.6.69<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.6.69`
- alert `424eacc3765ab380b6a170d2f69367fd` on lane `entity_key` = `10.42.6.69`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `parent_image`=C:\Windows\explorer.exe\npm.cmd<br>`original_filename`=PowerShell.EXE<br>`hostname`=HR-WKS-116<br>`agent_ip`=10.42.7.69<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.7.69`
- alert `5dc873c4490069f4a8bcd1d33a62f1be` on lane `entity_key` = `10.42.7.69`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\cmd.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `parent_image`=C:\Windows\node.exe<br>`image_path`=C:\Windows\System32\cmd.exe.bak<br>`hostname`=FIN-WKS-115<br>`agent_ip`=10.42.6.69<br>… | image_path=C:\Windows\System32\cmd.exe.bak fails 'image_path regex .*\Q\cmd.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.6.69`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'parent_image regex .*\Q\node.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `parent_image`=C:\Windows\node.exe.bak<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-115<br>`agent_ip`=10.42.6.69<br>… | parent_image=C:\Windows\node.exe.bak fails 'parent_image regex .*\Q\node.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.6.69`

