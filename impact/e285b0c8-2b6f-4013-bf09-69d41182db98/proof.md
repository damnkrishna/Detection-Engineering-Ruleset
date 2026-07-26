# Proof — e285b0c8-2b6f-4013-bf09-69d41182db98

## Rule

- **Rule ID:** e285b0c8-2b6f-4013-bf09-69d41182db98
- **Rule name:** Hosts File Tampering or Static DNS Routing Modification (AN0702-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [impact] / [T1565.002]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id eq 11 | `11` |
| `file_path` | file_path regex .*\Q\drivers\etc\hosts\E$ | `C:\Users\j.mercer\AppData\Local\Temp\drivers\etc\hosts` |
| `image_path` | image_path not_regex .*\Q\system32\svchost.exe\E$ AND image_path not_regex .*\Q\system32\notepad.exe\E$ AND image_path not_regex .*\Q\gpupdate.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\drivers\etc\hosts<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=OPS-WKS-833<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.124.148`
- alert `b6d8024bd5e91c4694f7ee9c3fa23817` on lane `entity_key` = `10.42.124.148`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp\drivers\e…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`parent_image`=C:\Windows\explorer.exe<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.123.148`
- alert `9b5e720b1e8d239fc1e7aebb6a399f0f` on lane `entity_key` = `10.42.123.148`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\gpupdate.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\drivers\etc\hosts<br>`image_path`=\gpupdate.exe<br>`hostname`=OPS-WKS-833<br>… | image_path=\gpupdate.exe fails 'image_path not_regex .*\Q\gpupdate.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.124.148`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'file_path regex .*\Q\drivers\etc\hosts\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\drivers\etc\hosts.bak<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=OPS-WKS-833<br>… | file_path=C:\Users\j.mercer\AppData\Local\Temp\drivers\etc\hosts.bak fails 'file_path regex .*\Q\drivers\etc\hosts\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.124.148`

