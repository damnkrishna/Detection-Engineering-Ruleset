# Proof — 2601ce9e-fa47-4bf2-85b1-cbcff931ec0a

## Rule

- **Rule ID:** 2601ce9e-fa47-4bf2-85b1-cbcff931ec0a
- **Rule name:** Unofficial DHCP Server Port Binding (AN1290-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [collection] / [T1557.003]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id eq 3 | `3` |
| `src_port` | src_port in_list [67] | `67` |
| `image_path` | image_path regex .*\Q\python.exe\E$ AND image_path not_regex .*\Q\svchost.exe\E$ AND image_path not_regex .*\Q\vmnat.exe\E$ AND image_path not_regex .*\Q\vmware-natd.exe\E$ AND image_path not_regex .*\Q\vboxsvc.exe\E$ | `C:\Windows\System32\python.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`src_port`=67<br>`image_path`=C:\Windows\System32\python.exe<br>`hostname`=FIN-WKS-120<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.11.187`
- alert `131c84a8025adeb7b8cba2eb2a2258fa` on lane `entity_key` = `10.42.11.187`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=3<br>`src_port`=67<br>`image_path`=C:\Windows\System32\cmd.exe\python3.exe<br>`hostname`=HR-WKS-121<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.12.187`
- alert `b2ff3d0640fca400f231385fe7b89395` on lane `entity_key` = `10.42.12.187`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\vboxsvc.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`src_port`=67<br>`image_path`=\vboxsvc.exe<br>`hostname`=FIN-WKS-120<br>… | image_path=\vboxsvc.exe fails 'image_path not_regex .*\Q\vboxsvc.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.11.187`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'src_port in_list [67]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`src_port`=67.bak<br>`image_path`=C:\Windows\System32\python.exe<br>`hostname`=FIN-WKS-120<br>… | src_port=67.bak fails 'src_port in_list [67]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.11.187`

