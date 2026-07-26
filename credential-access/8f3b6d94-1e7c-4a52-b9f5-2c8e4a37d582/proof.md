# Proof — 8f3b6d94-1e7c-4a52-b9f5-2c8e4a37d582

## Rule

- **Rule ID:** 8f3b6d94-1e7c-4a52-b9f5-2c8e4a37d582
- **Rule name:** Forced Authentication via UNC Path or SCF File Creation (AN2104)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [credential-access] / [T1187]
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
| `cmd_line` | cmd_line regex (?i)net(1)?\s+use\s+\\\\\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} AND cmd_line not_contains \\10. AND cmd_line not_contains \\192.168. AND cmd_line not_contains \\172.16. AND cmd_line not_contains \\172.17. AND cmd_line not_contains \\172.18. AND cmd_line not_contains \\172.19. AND cmd_line not_contains \\172.20. AND cmd_line not_contains \\172.21. AND cmd_line not_contains \\172.22. AND cmd_line not_contains \\172.23. AND cmd_line not_contains \\172.24. AND cmd_line not_contains \\172.25. AND cmd_line not_contains \\172.26. AND cmd_line not_contains \\172.27. AND cmd_line not_contains \\172.28. AND cmd_line not_contains \\172.29. AND cmd_line not_contains \\172.30. AND cmd_line not_contains \\172.31. | `net use \\1.1.1.1` |
| `image_path` | image_path regex .*\Q\net.exe\E$ | `C:\Windows\System32\net.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`=net use \\1.1.1.1<br>`image_path`=C:\Windows\System32\net.exe<br>`hostname`=ENG-WKS-087<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.178.162`
- alert `89b7c0317897c3aadd15c7662c396b25` on lane `entity_key` = `10.42.178.162`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`=New-PSDrivex\\1.1<br>`original_filename`=pwsh.exe<br>`hostname`=OPS-WKS-088<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.179.162`
- alert `5242bce859d69febd8c1452fdf2f15ec` on lane `entity_key` = `10.42.179.162`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line not_contains \\172.31.' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami \\172.31.<br>`image_path`=C:\Windows\System32\net.exe<br>`hostname`=ENG-WKS-087<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami \\172.31. fails 'cmd_line not_contains \\172.31.' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.178.162`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\net.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`=net use \\1.1.1.1<br>`image_path`=C:\Windows\System32\net.exe.bak<br>`hostname`=ENG-WKS-087<br>… | image_path=C:\Windows\System32\net.exe.bak fails 'image_path regex .*\Q\net.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.178.162`

