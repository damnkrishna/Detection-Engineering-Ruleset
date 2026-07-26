# Proof — 5d207b72-a79b-4bdf-8258-6f116311c385

## Rule

- **Rule ID:** 5d207b72-a79b-4bdf-8258-6f116311c385
- **Rule name:** Static Web Page Modification by Non-Webserver Process (AN0662-A)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [impact] / [T1491]
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
| `file_path` | file_path contains \inetpub\wwwroot\ AND file_path regex .*\Q.html\E$ | `C:\Users\j.mercer\AppData\Local\Temp\inetpub\wwwroot\.html` |
| `image_path` | image_path not_regex .*\Q\w3wp.exe\E$ AND image_path not_regex .*\Q\httpd.exe\E$ AND image_path not_regex .*\Q\nginx.exe\E$ AND image_path not_regex .*\Q\tomcat.exe\E$ AND image_path not_regex .*\Q\msdeploy.exe\E$ AND image_path not_regex .*\Q\notepad.exe\E$ AND image_path not_regex .*\Q\code.exe\E$ AND image_path not_regex .*\Q\explorer.exe\E$ | `C:\Windows\System32\cmd.exe` |
| `parent_image` | parent_image not_regex .*\Q\msdeploy.exe\E$ AND parent_image not_regex .*\Q\git.exe\E$ AND parent_image not_regex .*\Q\svn.exe\E$ | `C:\Windows\explorer.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\inetpub\wwwroot\.html<br>`image_path`=C:\Windows\System32\cmd.exe<br>`parent_image`=C:\Windows\explorer.exe<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.63.116`
- alert `6b57e6f3101e9a2423242c759c880b1a` on lane `entity_key` = `10.42.63.116`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp\apache\ht…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`parent_image`=C:\Windows\explorer.exe<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.64.116`
- alert `e4418b8f0000a65df83a211ceb671d55` on lane `entity_key` = `10.42.64.116`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'parent_image not_regex .*\Q\svn.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\inetpub\wwwroot\.html<br>`image_path`=C:\Windows\System32\cmd.exe<br>`parent_image`=\svn.exe<br>… | parent_image=\svn.exe fails 'parent_image not_regex .*\Q\svn.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.63.116`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\explorer.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\inetpub\wwwroot\.html<br>`image_path`=\explorer.exe<br>`parent_image`=C:\Windows\explorer.exe<br>… | image_path=\explorer.exe fails 'image_path not_regex .*\Q\explorer.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.63.116`

