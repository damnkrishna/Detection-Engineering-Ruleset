# Proof — b2c3d4e5-f6a7-4b8c-9d0e-1a2b3c4d5e6f

## Rule

- **Rule ID:** b2c3d4e5-f6a7-4b8c-9d0e-1a2b3c4d5e6f
- **Rule name:** Suspicious Process Spawning from Web Server Parent (AN2069-WebShell-Spawning)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [execution] / [T1505.003]
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
| `parent_image` | parent_image regex .*\Q\w3wp.exe\E$ | `C:\Windows\w3wp.exe` |
| `image_path` | image_path regex .*\Q\cmd.exe\E$ | `C:\Windows\System32\cmd.exe` |
| `username` | username not_regex NETWORK SERVICE\|IIS AppPool | `CORP\j.mercer` |
| `cmd_line` | cmd_line not_contains iisreset AND cmd_line not_contains logrotate AND cmd_line not_contains systemctl | `"C:\Windows\System32\cmd.exe" /c whoami` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`parent_image`=C:\Windows\w3wp.exe<br>`image_path`=C:\Windows\System32\cmd.exe<br>`username`=CORP\j.mercer<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `CORP\j.mercer`
- alert `547e56fa0138e76350c007ee23eb6d77` on lane `entity_key` = `CORP\j.mercer`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`parent_image`=C:\Windows\explorer.exe\httpd.exe<br>`image_path`=C:\Windows\System32\cmd.exe\powershell.exe<br>`username`=CORP\j.mercer<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `CORP\j.mercer`
- alert `0ddf3ac2080ea19ea079ee8832c6d3ff` on lane `entity_key` = `CORP\j.mercer`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line not_contains systemctl' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`parent_image`=C:\Windows\w3wp.exe<br>`image_path`=C:\Windows\System32\cmd.exe<br>`username`=CORP\j.mercer<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami systemctl fails 'cmd_line not_contains systemctl' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `CORP\j.mercer`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'username not_regex NETWORK SERVICE\|IIS AppPool' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`parent_image`=C:\Windows\w3wp.exe<br>`image_path`=C:\Windows\System32\cmd.exe<br>`username`=NETWORK SERVICE<br>… | username=NETWORK SERVICE fails 'username not_regex NETWORK SERVICE\|IIS AppPool' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.49.76`

