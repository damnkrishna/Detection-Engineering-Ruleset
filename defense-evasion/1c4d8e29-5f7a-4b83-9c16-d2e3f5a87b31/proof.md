# Proof — 1c4d8e29-5f7a-4b83-9c16-d2e3f5a87b31

## Rule

- **Rule ID:** 1c4d8e29-5f7a-4b83-9c16-d2e3f5a87b31
- **Rule name:** Indirect Command Execution via Trusted Windows Utilities (AN2100)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [defense-evasion] / [T1202]
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
| `cmd_line` | cmd_line contains /c  AND cmd_line not_contains cmd /c del AND cmd_line not_contains cmd /c type AND cmd_line not_contains cmd /c move | `"C:\Windows\System32\cmd.exe" /c C:\Users\Public\export.dat` |
| `image_path` | image_path regex .*\Q\forfiles.exe\E$ | `C:\Windows\System32\forfiles.exe` |
| `parent_image` | parent_image not_regex .*\Q\taskeng.exe\E$ AND parent_image not_regex .*\Q\svchost.exe\E$ | `C:\Windows\explorer.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c C:\Users\Public\export.dat<br>`image_path`=C:\Windows\System32\forfiles.exe<br>`parent_image`=C:\Windows\explorer.exe<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.188.189`
- alert `bb7b4123f6a9f8178838e4d23063c4fb` on lane `entity_key` = `10.42.188.189`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami -a C:\Users\Publi…<br>`original_filename`=pcalua.exe<br>`parent_image`=C:\Windows\explorer.exe<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.187.189`
- alert `8856eb3fecc6a2854619e9e69a44103d` on lane `entity_key` = `10.42.187.189`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line not_contains cmd /c move' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami cmd /c move<br>`image_path`=C:\Windows\System32\forfiles.exe<br>`parent_image`=C:\Windows\explorer.exe<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami cmd /c move fails 'cmd_line not_contains cmd /c move' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.188.189`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'parent_image not_regex .*\Q\svchost.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c C:\Users\Public\export.dat<br>`image_path`=C:\Windows\System32\forfiles.exe<br>`parent_image`=\svchost.exe<br>… | parent_image=\svchost.exe fails 'parent_image not_regex .*\Q\svchost.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.188.189`

