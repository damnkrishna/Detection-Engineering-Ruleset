# Proof — 454c6183-48a4-44de-a265-6bd9b0cf49e8

## Rule

- **Rule ID:** 454c6183-48a4-44de-a265-6bd9b0cf49e8
- **Rule name:** Outbound Connections to Amplification Ports (AN1140-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [impact] / [T1498.002]
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
| `dst_port` | dst_port in_list [11211, 1900, 161] | `11211` |
| `image_path` | image_path not_regex .*\Q\system32\svchost.exe\E$ AND image_path not_regex .*\Q\system32\snmp.exe\E$ AND image_path not_regex .*\Q\chrome.exe\E$ AND image_path not_regex .*\Q\firefox.exe\E$ | `C:\Windows\System32\cmd.exe` |
| `dst_ip` | dst_ip not_starts_with 224. AND dst_ip not_starts_with 239. AND dst_ip not_starts_with 255.255.255.255 AND dst_ip not_starts_with ff | `198.51.100.24` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`dst_port`=11211<br>`image_path`=C:\Windows\System32\cmd.exe<br>`dst_ip`=198.51.100.24<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.48.83`
- alert `3b8e8b6be5847015f30400a237fc7392` on lane `entity_key` = `10.42.48.83`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=3<br>`dst_port`=1900<br>`image_path`=C:\Windows\System32\cmd.exe<br>`dst_ip`=198.51.100.24<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.49.83`
- alert `b69450df792a31d330e64d6000fb577a` on lane `entity_key` = `10.42.49.83`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'dst_ip not_starts_with ff' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`dst_port`=11211<br>`image_path`=C:\Windows\System32\cmd.exe<br>`dst_ip`=ff198.51.100.24<br>… | dst_ip=ff198.51.100.24 fails 'dst_ip not_starts_with ff' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.48.83`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\firefox.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`dst_port`=11211<br>`image_path`=\firefox.exe<br>`dst_ip`=198.51.100.24<br>… | image_path=\firefox.exe fails 'image_path not_regex .*\Q\firefox.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.48.83`

