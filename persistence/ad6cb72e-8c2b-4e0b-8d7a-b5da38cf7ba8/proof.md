# Proof — ad6cb72e-8c2b-4e0b-8d7a-b5da38cf7ba8

## Rule

- **Rule ID:** ad6cb72e-8c2b-4e0b-8d7a-b5da38cf7ba8
- **Rule name:** Malicious IIS Component File Drop (AN0184-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [persistence] / [T1505.004]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `file_path` | file_path contains \System32\inetsrv\ AND file_path regex .*\Q.dll\E$ | `C:\Users\j.mercer\AppData\Local\Temp\System32\inetsrv\.dll` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\System32\inetsrv\.dll<br>`hostname`=FIN-WKS-355<br>`agent_ip`=10.42.146.178<br>`event_id`=11<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.146.178`
- alert `f9e1336dabd345eb95e4015d341fbb23` on lane `entity_key` = `10.42.146.178`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp\inetsrv\c…<br>`hostname`=HR-WKS-356<br>`agent_ip`=10.42.147.178<br>`event_id`=11<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.147.178`
- alert `cf06c2ca777939b34d0514a1d4ab9f29` on lane `entity_key` = `10.42.147.178`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'file_path regex .*\Q.dll\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\System32\inetsrv\.dl…<br>`hostname`=FIN-WKS-355<br>`agent_ip`=10.42.146.178<br>`event_id`=11<br>… | file_path=C:\Users\j.mercer\AppData\Local\Temp\System32\inetsrv\.dll.bak fails 'file_path regex .*\Q.dll\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.146.178`

## benign_2

**Expected alerts:** 0  
**Construction:** the field 'file_path' is absent entirely; an absent field is no-match for every operator, so the stage is never entered

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `hostname`=FIN-WKS-355<br>`agent_ip`=10.42.146.178<br>`event_id`=11<br>`image_path`=C:\Windows\System32\cmd.exe<br>… | carries no 'file_path' at all; evaluateCondition returns no-match for every operator on an absent field, so the stage gate rejects the event |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.146.178`

