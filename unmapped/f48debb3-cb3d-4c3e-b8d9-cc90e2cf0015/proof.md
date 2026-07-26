# Proof — f48debb3-cb3d-4c3e-b8d9-cc90e2cf0015

## Rule

- **Rule ID:** f48debb3-cb3d-4c3e-b8d9-cc90e2cf0015
- **Rule name:** Download Utility Spawned by User Application (AN0962-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [execution] / [T1204.004]
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
| `parent_image` | parent_image regex .*\Q\chrome.exe\E$ AND parent_image not_regex .*\Q\msiexec.exe\E$ AND parent_image not_regex .*\Q\setup.exe\E$ AND parent_image not_regex .*\Q\update.exe\E$ | `C:\Windows\chrome.exe` |
| `image_path` | image_path regex .*\Q\curl.exe\E$ | `C:\Windows\System32\curl.exe` |
| `cmd_line` | cmd_line not_contains \AppData\Local\Google\Update\ AND cmd_line not_contains \AppData\Local\Microsoft\EdgeUpdate\ AND cmd_line not_contains \AppData\Local\Temp\ | `"C:\Windows\System32\cmd.exe" /c whoami` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`parent_image`=C:\Windows\chrome.exe<br>`image_path`=C:\Windows\System32\curl.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.63.195`
- alert `9219a583eb6d40ea9b691ba2a2d2732d` on lane `entity_key` = `10.42.63.195`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`parent_image`=C:\Windows\explorer.exe\msedge.exe<br>`image_path`=C:\Windows\System32\cmd.exe\wget.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.64.195`
- alert `1ae09842ecba011871860dfedc5d388d` on lane `entity_key` = `10.42.64.195`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'parent_image not_regex .*\Q\update.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`parent_image`=\update.exe<br>`image_path`=C:\Windows\System32\curl.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>… | parent_image=\update.exe fails 'parent_image not_regex .*\Q\update.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.63.195`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line not_contains \AppData\Local\Temp\' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`parent_image`=C:\Windows\chrome.exe<br>`image_path`=C:\Windows\System32\curl.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami \AppData\Local\Temp\<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami \AppData\Local\Temp\ fails 'cmd_line not_contains \AppData\Local\Temp\' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.63.195`

