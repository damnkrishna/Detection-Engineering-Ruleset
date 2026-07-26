# Proof — 00ccaca1-f523-4ad1-b89d-1d6e56b834ab

## Rule

- **Rule ID:** 00ccaca1-f523-4ad1-b89d-1d6e56b834ab
- **Rule name:** Local System Shutdown/Reboot Invocations (AN1538-A)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [impact] / [T1529]
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
| `image_path` | image_path regex .*\Q\shutdown.exe\E$ | `C:\Windows\System32\shutdown.exe` |
| `cmd_line` | cmd_line contains  /s | `"C:\Windows\System32\cmd.exe"  /s` |
| `parent_image` | parent_image not_regex .*\Q\tiworker.exe\E$ AND parent_image not_regex .*\Q\svchost.exe\E$ AND parent_image not_regex .*\Q\trustedinstaller.exe\E$ | `C:\Windows\explorer.exe` |
| `username` | username neq NT AUTHORITY\SYSTEM | `CORP\j.mercer` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\shutdown.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe"  /s<br>`parent_image`=C:\Windows\explorer.exe<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `CORP\j.mercer`
- alert `6d3fb77b7df79904274082ae7a58306f` on lane `entity_key` = `CORP\j.mercer`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami Restart-Computer<br>`parent_image`=C:\Windows\explorer.exe<br>`username`=CORP\j.mercer<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `CORP\j.mercer`
- alert `c35cfde0a15150be4658ebd44a7617a0` on lane `entity_key` = `CORP\j.mercer`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'username neq NT AUTHORITY\SYSTEM' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\shutdown.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe"  /s<br>`parent_image`=C:\Windows\explorer.exe<br>… | username=NT AUTHORITY\SYSTEM fails 'username neq NT AUTHORITY\SYSTEM' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `NT AUTHORITY\SYSTEM`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'parent_image not_regex .*\Q\trustedinstaller.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\shutdown.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe"  /s<br>`parent_image`=\trustedinstaller.exe<br>… | parent_image=\trustedinstaller.exe fails 'parent_image not_regex .*\Q\trustedinstaller.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `CORP\j.mercer`

