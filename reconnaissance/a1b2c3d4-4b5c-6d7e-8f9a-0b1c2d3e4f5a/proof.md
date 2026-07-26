# Proof — a1b2c3d4-4b5c-6d7e-8f9a-0b1c2d3e4f5a

## Rule

- **Rule ID:** a1b2c3d4-4b5c-6d7e-8f9a-0b1c2d3e4f5a
- **Rule name:** Registry System Information Query (AN2067-Registry)
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
| `image_path` | image_path regex .*\Q\reg.exe\E$ | `C:\Windows\System32\reg.exe` |
| `original_filename` | original_filename eq reg.exe | `reg.exe` |
| `cmd_line` | cmd_line contains query AND cmd_line contains HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion | `"C:\Windows\System32\cmd.exe" query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\reg.exe<br>`original_filename`=reg.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" query HKLM\SOFTWARE\Microso…<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.46.124`
- alert `7a30883fbf8532a22ac76f69398b2f60` on lane `entity_key` = `10.42.46.124`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\cmd.exe\reg.exe<br>`original_filename`=reg.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami query HKLM\SYSTEM…<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.47.124`
- alert `b5790bb7b7bb82ea22d8007233b4decb` on lane `entity_key` = `10.42.47.124`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\reg.exe<br>`original_filename`=reg.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" query HKLM\SOFTWARE\Microso…<br>… | cmd_line="C:\Windows\System32\cmd.exe" query HKLM\SOFTWARE\Microsoft\Windows NT\contoso-CurrentVersion fails 'cmd_line contains HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.46.124`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'original_filename eq reg.exe' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\reg.exe<br>`original_filename`=reg.exe.bak<br>`cmd_line`="C:\Windows\System32\cmd.exe" query HKLM\SOFTWARE\Microso…<br>… | original_filename=reg.exe.bak fails 'original_filename eq reg.exe' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.46.124`

