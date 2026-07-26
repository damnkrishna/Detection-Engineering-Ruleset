# Proof — cdef9001-a189-4db8-bb9a-7c9802cf0040

## Rule

- **Rule ID:** cdef9001-a189-4db8-bb9a-7c9802cf0040
- **Rule name:** System Service Enumeration (AN2076)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [discovery] / [T1007]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id eq 1 | `1` |
| `cmd_line` | cmd_line contains  query | `"C:\Windows\System32\cmd.exe"  query` |
| `image_path` | image_path regex .*\Q\sc.exe\E$ | `C:\Windows\System32\sc.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`="C:\Windows\System32\cmd.exe"  query<br>`image_path`=C:\Windows\System32\sc.exe<br>`hostname`=SEC-WKS-414<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.105.141`
- alert `2c65a42c42d920baee4f0b5a8abbf665` on lane `entity_key` = `10.42.105.141`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami query<br>`original_filename`=net.exe<br>`hostname`=OPS-WKS-413<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.104.141`
- alert `a7d313faa267218dc3a30b79badc6d85` on lane `entity_key` = `10.42.104.141`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\sc.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`="C:\Windows\System32\cmd.exe"  query<br>`image_path`=C:\Windows\System32\sc.exe.bak<br>`hostname`=SEC-WKS-414<br>… | image_path=C:\Windows\System32\sc.exe.bak fails 'image_path regex .*\Q\sc.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.105.141`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains  query' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>`image_path`=C:\Windows\System32\sc.exe<br>`hostname`=SEC-WKS-414<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami fails 'cmd_line contains  query' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.105.141`

