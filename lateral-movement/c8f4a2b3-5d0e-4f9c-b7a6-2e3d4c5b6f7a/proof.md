# Proof — c8f4a2b3-5d0e-4f9c-b7a6-2e3d4c5b6f7a

## Rule

- **Rule ID:** c8f4a2b3-5d0e-4f9c-b7a6-2e3d4c5b6f7a
- **Rule name:** VNC Network Connection on Default Port (AN0504-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [lateral-movement] / [T1021.005]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `dst_port` | dst_port eq 5900 | `5900` |
| `image_path` | image_path not_contains \Program Files\RealVNC\ AND image_path not_contains \Program Files\TightVNC\ AND image_path not_contains \Program Files\UltraVNC\ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `dst_port`=5900<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=SEC-WKS-084<br>`agent_ip`=10.42.175.169<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.175.169`
- alert `6438d66d226db910ea5b1861e46d469e` on lane `entity_key` = `10.42.175.169`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `image_path`=C:\Windows\System32\cmd.exe\tvnserver.exe<br>`hostname`=OPS-WKS-083<br>`agent_ip`=10.42.174.169<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.174.169`
- alert `372bf02ec4058d74af5a9d4346dd9c32` on lane `entity_key` = `10.42.174.169`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_contains \Program Files\UltraVNC\' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `dst_port`=5900<br>`image_path`=C:\Windows\System32\cmd.exe \Program Files\UltraVNC\<br>`hostname`=SEC-WKS-084<br>`agent_ip`=10.42.175.169<br>… | image_path=C:\Windows\System32\cmd.exe \Program Files\UltraVNC\ fails 'image_path not_contains \Program Files\UltraVNC\' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.175.169`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'dst_port eq 5900' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `dst_port`=5900.bak<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=SEC-WKS-084<br>`agent_ip`=10.42.175.169<br>… | dst_port=5900.bak fails 'dst_port eq 5900' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.175.169`

