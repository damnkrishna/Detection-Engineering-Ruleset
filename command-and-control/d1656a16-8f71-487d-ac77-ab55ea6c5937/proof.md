# Proof — d1656a16-8f71-487d-ac77-ab55ea6c5937

## Rule

- **Rule ID:** d1656a16-8f71-487d-ac77-ab55ea6c5937
- **Rule name:** Ingress Tool Transfer Network Connection (AN0165-C)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [command-and-control] / [T1105]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `dst_port` | dst_port in_list [80, 443, 8080] | `80` |
| `image_path` | image_path regex .*\Q\certutil.exe\E$ | `C:\Windows\System32\certutil.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `dst_port`=80<br>`image_path`=C:\Windows\System32\certutil.exe<br>`hostname`=ENG-WKS-232<br>`agent_ip`=10.42.23.35<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.23.35`
- alert `a093f104950fb06f4f253473757d3a21` on lane `entity_key` = `10.42.23.35`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `dst_port`=443<br>`image_path`=C:\Windows\System32\cmd.exe\bitsadmin.exe<br>`hostname`=HR-WKS-231<br>`agent_ip`=10.42.22.35<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.22.35`
- alert `d6829af03a014c6e72428d9c851d0b66` on lane `entity_key` = `10.42.22.35`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\certutil.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `dst_port`=80<br>`image_path`=C:\Windows\System32\certutil.exe.bak<br>`hostname`=ENG-WKS-232<br>`agent_ip`=10.42.23.35<br>… | image_path=C:\Windows\System32\certutil.exe.bak fails 'image_path regex .*\Q\certutil.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.23.35`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'dst_port in_list [80, 443, 8080]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `dst_port`=80.bak<br>`image_path`=C:\Windows\System32\certutil.exe<br>`hostname`=ENG-WKS-232<br>`agent_ip`=10.42.23.35<br>… | dst_port=80.bak fails 'dst_port in_list [80, 443, 8080]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.23.35`

