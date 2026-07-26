# Proof — 4928e1de-dfad-467d-97fb-ecddb53471b2

## Rule

- **Rule ID:** 4928e1de-dfad-467d-97fb-ecddb53471b2
- **Rule name:** Pass the Ticket Kerberos Command Line (AN1000)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [lateral-movement] / [T1550.003]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `cmd_line` | cmd_line contains ptt  | `"C:\Windows\System32\cmd.exe" ptt C:\Users\Public\export.dat` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe" ptt C:\Users\Public\export.dat<br>`hostname`=OPS-WKS-603<br>`agent_ip`=10.42.194.76<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.194.76`
- alert `2fdbe3feb65c2c9e0ebaf70f96647098` on lane `entity_key` = `10.42.194.76`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe" /c whoami asktgt C:\Users\P…<br>`hostname`=SEC-WKS-604<br>`agent_ip`=10.42.195.76<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.195.76`
- alert `5b5679c267aba4d0f6cb5d8f4f40c793` on lane `entity_key` = `10.42.195.76`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains ptt ' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>`hostname`=OPS-WKS-603<br>`agent_ip`=10.42.194.76<br>`event_id`=1<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami fails 'cmd_line contains ptt ' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.194.76`

## benign_2

**Expected alerts:** 0  
**Construction:** the field 'cmd_line' is absent entirely; an absent field is no-match for every operator, so the stage is never entered

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `hostname`=OPS-WKS-603<br>`agent_ip`=10.42.194.76<br>`event_id`=1<br>`image_path`=C:\Windows\System32\cmd.exe<br>… | carries no 'cmd_line' at all; evaluateCondition returns no-match for every operator on an absent field, so the stage gate rejects the event |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.194.76`

