# Proof — 06ef5fb3-ef8f-4874-8c2d-42009fa58b58

## Rule

- **Rule ID:** 06ef5fb3-ef8f-4874-8c2d-42009fa58b58
- **Rule name:** Windows Service Service Account PowerShell Execution (AN0327-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [lateral-movement] / [T1210]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `username` | username contains NT AUTHORITY\SYSTEM | `CORP NT AUTHORITY\SYSTEM` |
| `script_block_text` | script_block_text contains PrintNightmare | `Get-Process \| Select-Object Name, Id PrintNightmare` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `username`=CORP NT AUTHORITY\SYSTEM<br>`script_block_text`=Get-Process \| Select-Object Name, Id PrintNightmare<br>`hostname`=HR-WKS-501<br>`agent_ip`=10.42.192.73<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `CORP NT AUTHORITY\SYSTEM`
- alert `7dcf89dc17f91a205ab7b5e617d5d508` on lane `entity_key` = `CORP NT AUTHORITY\SYSTEM`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `username`=CORP\j.mercer NT AUTHORITY\NETWORK SERVICE<br>`script_block_text`=C:\Windows\System32 spoolsv<br>`hostname`=ENG-WKS-502<br>`agent_ip`=10.42.193.73<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `CORP\j.mercer NT AUTHORITY\NETWORK SERVICE`
- alert `5af531fdcd58430a5be29d8f6d5d371b` on lane `entity_key` = `CORP\j.mercer NT AUTHORITY\NETWORK SERVICE`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'script_block_text contains PrintNightmare' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `username`=CORP NT AUTHORITY\SYSTEM<br>`script_block_text`=Get-Process \| Select-Object Name, Id<br>`hostname`=HR-WKS-501<br>`agent_ip`=10.42.192.73<br>… | script_block_text=Get-Process \| Select-Object Name, Id fails 'script_block_text contains PrintNightmare' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `CORP NT AUTHORITY\SYSTEM`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'username contains NT AUTHORITY\SYSTEM' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `username`=CORP\j.mercer<br>`script_block_text`=Get-Process \| Select-Object Name, Id PrintNightmare<br>`hostname`=HR-WKS-501<br>`agent_ip`=10.42.192.73<br>… | username=CORP\j.mercer fails 'username contains NT AUTHORITY\SYSTEM' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `CORP\j.mercer`

