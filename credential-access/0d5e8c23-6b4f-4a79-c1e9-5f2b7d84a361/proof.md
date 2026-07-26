# Proof — 0d5e8c23-6b4f-4a79-c1e9-5f2b7d84a361

## Rule

- **Rule ID:** 0d5e8c23-6b4f-4a79-c1e9-5f2b7d84a361
- **Rule name:** Browser Cookie Database Access by Non-Browser Process (AN2107)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [credential-access] / [T1539]
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
| `image_path` | image_path regex .*\Q\sqlite3.exe\E$ | `C:\Windows\System32\sqlite3.exe` |
| `cmd_line` | cmd_line contains AppData\Local\Google\Chrome\User Data | `"C:\Windows\System32\cmd.exe" AppData\Local\Google\Chrome\User Data` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\sqlite3.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" AppData\Local\Google\Chrome…<br>`hostname`=OPS-WKS-443<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.134.29`
- alert `d44eec3fa6127428dc29579f3c8986c0` on lane `entity_key` = `10.42.134.29`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`original_filename`=pwsh.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami Edge\User Data<br>`hostname`=ENG-WKS-442<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.133.29`
- alert `1563548a3dcaa8fd6fff7586dc11de84` on lane `entity_key` = `10.42.133.29`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains AppData\Local\Google\Chrome\User Data' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\sqlite3.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" AppData\Local\Google\Chrome…<br>`hostname`=OPS-WKS-443<br>… | cmd_line="C:\Windows\System32\cmd.exe" AppData\Local\Google\Chrome\contoso-User Data fails 'cmd_line contains AppData\Local\Google\Chrome\User Data' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.134.29`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\sqlite3.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\sqlite3.exe.bak<br>`cmd_line`="C:\Windows\System32\cmd.exe" AppData\Local\Google\Chrome…<br>`hostname`=OPS-WKS-443<br>… | image_path=C:\Windows\System32\sqlite3.exe.bak fails 'image_path regex .*\Q\sqlite3.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.134.29`

