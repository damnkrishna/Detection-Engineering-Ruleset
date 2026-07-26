# Proof — 5a8a1b24-9b2f-4c8d-8d4e-b5c6d7e8f9a0

## Rule

- **Rule ID:** 5a8a1b24-9b2f-4c8d-8d4e-b5c6d7e8f9a0
- **Rule name:** Suspicious System Information Gathering (AN2067)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [reconnaissance] / [T1592]
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
| `original_filename` | original_filename in_list [systeminfo.exe, dxdiag.exe, gpres.exe] | `systeminfo.exe` |
| `image_path` | image_path regex .*\Q\systeminfo.exe\E$ | `C:\Windows\System32\systeminfo.exe` |
| `cmd_line` | cmd_line contains /S | `"C:\Windows\System32\cmd.exe" /S` |
| `parent_cmd_line` | parent_cmd_line not_contains C:\Program Files\Diagnostic Tools\ AND parent_cmd_line not_contains C:\Windows\System32\drivers\etc\ | `C:\Windows\Explorer.EXE` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`original_filename`=systeminfo.exe<br>`image_path`=C:\Windows\System32\systeminfo.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /S<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.141.49`
- alert `39f1d64f5d84d0cf9b5733a9def4a571` on lane `entity_key` = `10.42.141.49`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`original_filename`=dxdiag.exe<br>`image_path`=C:\Windows\System32\cmd.exe\dxdiag.exe<br>`parent_image`=C:\Windows\explorer.exe C:\Users\Public\export.dat<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.142.49`
- alert `e4082d223bb7c2a3dcac34a0e408dfe3` on lane `entity_key` = `10.42.142.49`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'parent_cmd_line not_contains C:\Windows\System32\drivers\etc\' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`original_filename`=systeminfo.exe<br>`image_path`=C:\Windows\System32\systeminfo.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /S<br>… | parent_cmd_line=C:\Windows\Explorer.EXE C:\Windows\System32\drivers\etc\ fails 'parent_cmd_line not_contains C:\Windows\System32\drivers\etc\' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.141.49`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains /S' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`original_filename`=systeminfo.exe<br>`image_path`=C:\Windows\System32\systeminfo.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /contoso-S<br>… | cmd_line="C:\Windows\System32\cmd.exe" /contoso-S fails 'cmd_line contains /S' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.141.49`

