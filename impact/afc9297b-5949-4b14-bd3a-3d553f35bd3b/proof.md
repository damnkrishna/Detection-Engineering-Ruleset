# Proof — afc9297b-5949-4b14-bd3a-3d553f35bd3b

## Rule

- **Rule ID:** afc9297b-5949-4b14-bd3a-3d553f35bd3b
- **Rule name:** Potential Endpoint Service Exhaustion Flood Tool Execution via Network Connection (AN0489-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [impact] / [T1499.002]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `dst_port` | dst_port in_list [80, 443, 8080, 8443] | `80` |
| `image_path` | image_path regex .*\Q\powershell.exe\E$ | `C:\Windows\System32\powershell.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `dst_port`=80<br>`image_path`=C:\Windows\System32\powershell.exe<br>`hostname`=ENG-WKS-407<br>`agent_ip`=10.42.98.15<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.98.15`
- alert `cf72790b5204a66e5f64ab2dac5e7abd` on lane `entity_key` = `10.42.98.15`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `dst_port`=443<br>`image_path`=C:\Windows\System32\cmd.exe\pwsh.exe<br>`hostname`=OPS-WKS-408<br>`agent_ip`=10.42.99.15<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.99.15`
- alert `b05fefed5f321d8e63d98fea16dd74a5` on lane `entity_key` = `10.42.99.15`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\powershell.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `dst_port`=80<br>`image_path`=C:\Windows\System32\powershell.exe.bak<br>`hostname`=ENG-WKS-407<br>`agent_ip`=10.42.98.15<br>… | image_path=C:\Windows\System32\powershell.exe.bak fails 'image_path regex .*\Q\powershell.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.98.15`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'dst_port in_list [80, 443, 8080, 8443]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `dst_port`=80.bak<br>`image_path`=C:\Windows\System32\powershell.exe<br>`hostname`=ENG-WKS-407<br>`agent_ip`=10.42.98.15<br>… | dst_port=80.bak fails 'dst_port in_list [80, 443, 8080, 8443]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.98.15`

