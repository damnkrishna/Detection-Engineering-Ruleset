# Proof — 44b8766b-080d-4d8b-92e1-cfeb74990ac7

## Rule

- **Rule ID:** 44b8766b-080d-4d8b-92e1-cfeb74990ac7
- **Rule name:** Scripting Process Invoked as Proxy Listener (AN0823-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [collection] / [T1557]
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
| `image_path` | image_path regex .*\Q\python.exe\E$ | `C:\Windows\System32\python.exe` |
| `cmd_line` | cmd_line contains --listen-port | `"C:\Windows\System32\cmd.exe" --listen-port` |
| `parent_image` | parent_image not_regex .*\Q\msiexec.exe\E$ AND parent_image not_regex .*\Q\setup.exe\E$ | `C:\Windows\explorer.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\python.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" --listen-port<br>`parent_image`=C:\Windows\explorer.exe<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.80.99`
- alert `c703f5ae961326cade4b6152c9f41bb0` on lane `entity_key` = `10.42.80.99`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\cmd.exe\python3.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami--mode reverse<br>`parent_image`=C:\Windows\explorer.exe<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.79.99`
- alert `a466ada7fe18f42eac791f0c1235afda` on lane `entity_key` = `10.42.79.99`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'parent_image not_regex .*\Q\setup.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\python.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" --listen-port<br>`parent_image`=\setup.exe<br>… | parent_image=\setup.exe fails 'parent_image not_regex .*\Q\setup.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.80.99`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains --listen-port' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\python.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>`parent_image`=C:\Windows\explorer.exe<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami fails 'cmd_line contains --listen-port' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.80.99`

