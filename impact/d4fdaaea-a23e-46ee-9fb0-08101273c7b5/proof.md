# Proof — d4fdaaea-a23e-46ee-9fb0-08101273c7b5

## Rule

- **Rule ID:** d4fdaaea-a23e-46ee-9fb0-08101273c7b5
- **Rule name:** Outbound Network Connection to Cryptomining Stratum Pools (AN0741-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [impact] / [T1496]
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
| `dst_port` | dst_port in_list [3333, 4444, 5555, 7777, 14444] | `3333` |
| `image_path` | image_path not_regex .*\Q\chrome.exe\E$ AND image_path not_regex .*\Q\firefox.exe\E$ AND image_path not_regex .*\Q\msedge.exe\E$ AND image_path not_regex .*\Q\jupyter.exe\E$ | `C:\Windows\System32\cmd.exe` |
| `dst_ip` | dst_ip not_in_cidr 127.0.0.0/8 AND dst_ip not_in_cidr 10.0.0.0/8 AND dst_ip not_in_cidr 192.168.0.0/16 AND dst_ip not_in_cidr 172.16.0.0/12 | `198.51.100.24` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`dst_port`=3333<br>`image_path`=C:\Windows\System32\cmd.exe<br>`dst_ip`=198.51.100.24<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.151.164`
- alert `8b7495215be7a7d9fb2e13e99a2a4dc9` on lane `entity_key` = `10.42.151.164`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=3<br>`dst_port`=4444<br>`image_path`=C:\Windows\System32\cmd.exe<br>`dst_ip`=198.51.100.24<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.152.164`
- alert `a39a81bd214e97e22e32b2c7ffd77ac8` on lane `entity_key` = `10.42.152.164`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\jupyter.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`dst_port`=3333<br>`image_path`=\jupyter.exe<br>`dst_ip`=198.51.100.24<br>… | image_path=\jupyter.exe fails 'image_path not_regex .*\Q\jupyter.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.151.164`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'dst_port in_list [3333, 4444, 5555, 7777, 14444]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`dst_port`=3333.bak<br>`image_path`=C:\Windows\System32\cmd.exe<br>`dst_ip`=198.51.100.24<br>… | dst_port=3333.bak fails 'dst_port in_list [3333, 4444, 5555, 7777, 14444]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.151.164`

