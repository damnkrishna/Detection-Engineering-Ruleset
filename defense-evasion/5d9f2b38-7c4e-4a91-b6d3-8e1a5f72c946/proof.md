# Proof — 5d9f2b38-7c4e-4a91-b6d3-8e1a5f72c946

## Rule

- **Rule ID:** 5d9f2b38-7c4e-4a91-b6d3-8e1a5f72c946
- **Rule name:** XSL Script Execution via WMIC or MSXSL (AN2102)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [defense-evasion] / [T1220]
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
| `image_path` | image_path regex .*\Q\wmic.exe\E$ | `C:\Windows\System32\wmic.exe` |
| `cmd_line` | cmd_line contains /format: AND cmd_line not_regex (?i)/format:(list\|table\|csv\|hform\|htable\|value\|rawxml\|xml\|mof\|textvaluelist)(?:\s\|$) | `"C:\Windows\System32\cmd.exe" /format:` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\wmic.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /format:<br>`hostname`=HR-WKS-606<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.197.198`
- alert `3fb81d9188dae44e82015f9e9e6ee86a` on lane `entity_key` = `10.42.197.198`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\cmd.exe\msxsl.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>`hostname`=ENG-WKS-607<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.198.198`
- alert `24876ac973dfdb76fc3bbf383cad17d9` on lane `entity_key` = `10.42.198.198`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line not_regex (?i)/format:(list\|table\|csv\|hform\|htable\|value\|rawxml\|xml\|mof\|textvaluelist)(?:\s\|$)' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\wmic.exe<br>`cmd_line`=/format:list <br>`hostname`=HR-WKS-606<br>… | cmd_line=/format:list  fails 'cmd_line not_regex (?i)/format:(list\|table\|csv\|hform\|htable\|value\|rawxml\|xml\|mof\|textvaluelist)(?:\s\|$)' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.197.198`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\wmic.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\wmic.exe.bak<br>`cmd_line`="C:\Windows\System32\cmd.exe" /format:<br>`hostname`=HR-WKS-606<br>… | image_path=C:\Windows\System32\wmic.exe.bak fails 'image_path regex .*\Q\wmic.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.197.198`

