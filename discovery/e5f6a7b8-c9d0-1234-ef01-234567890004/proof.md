# Proof — e5f6a7b8-c9d0-1234-ef01-234567890004

## Rule

- **Rule ID:** e5f6a7b8-c9d0-1234-ef01-234567890004
- **Rule name:** Windows Event Log Enumeration (AN2091)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [discovery] / [T1654]
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
| `cmd_line` | cmd_line regex (?i)wevtutil(\.exe)?\s+(el\|gl\|qe\|epl)\b | `wevtutil el` |
| `image_path` | image_path regex .*\Q\wevtutil.exe\E$ | `C:\Windows\System32\wevtutil.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`=wevtutil el<br>`image_path`=C:\Windows\System32\wevtutil.exe<br>`hostname`=FIN-WKS-595<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.186.143`
- alert `dd4470fdbfff85ff516a0e9ebbd985b3` on lane `entity_key` = `10.42.186.143`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`original_filename`=pwsh.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami Get-WinEvent<br>`hostname`=SEC-WKS-594<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.185.143`
- alert `87e317d497845a2c294b34c296e8ef11` on lane `entity_key` = `10.42.185.143`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\wevtutil.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`=wevtutil el<br>`image_path`=C:\Windows\System32\wevtutil.exe.bak<br>`hostname`=FIN-WKS-595<br>… | image_path=C:\Windows\System32\wevtutil.exe.bak fails 'image_path regex .*\Q\wevtutil.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.186.143`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line regex (?i)wevtutil(\.exe)?\s+(el\|gl\|qe\|epl)\b' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>`image_path`=C:\Windows\System32\wevtutil.exe<br>`hostname`=FIN-WKS-595<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami fails 'cmd_line regex (?i)wevtutil(\.exe)?\s+(el\|gl\|qe\|epl)\b' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.186.143`

