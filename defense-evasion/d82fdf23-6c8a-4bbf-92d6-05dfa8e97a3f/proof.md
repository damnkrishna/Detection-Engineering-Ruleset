# Proof — d82fdf23-6c8a-4bbf-92d6-05dfa8e97a3f

## Rule

- **Rule ID:** d82fdf23-6c8a-4bbf-92d6-05dfa8e97a3f
- **Rule name:** Electron ASAR File Modification (AN0071-C)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [defense-evasion] / [T1218.015]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `file_path` | file_path regex .*\Q\.asar\E$ AND file_path contains \Microsoft\Teams\ | `C:\Users\j.mercer\AppData\Local\Temp\Microsoft\Teams\\.asar` |
| `image_path` | image_path not_regex .*\Q\Teams.exe\E$ AND image_path not_regex .*\Q\slack.exe\E$ AND image_path not_regex .*\Q\Code.exe\E$ AND image_path not_regex .*\Q\Discord.exe\E$ AND image_path not_regex .*\Q\Update.exe\E$ AND image_path not_regex .*\Q\Squirrel.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\Microsoft\Teams\\.asar<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=ENG-WKS-262<br>`agent_ip`=10.42.153.66<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.153.66`
- alert `128871b9c24d63a78b7f5dc104404c8d` on lane `entity_key` = `10.42.153.66`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp\Slack\\.asar<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=OPS-WKS-263<br>`agent_ip`=10.42.154.66<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.154.66`
- alert `ed576fcffbd0ab114e7c774e454f62fa` on lane `entity_key` = `10.42.154.66`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\Squirrel.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\Microsoft\Teams\\.asar<br>`image_path`=\Squirrel.exe<br>`hostname`=ENG-WKS-262<br>`agent_ip`=10.42.153.66<br>… | image_path=\Squirrel.exe fails 'image_path not_regex .*\Q\Squirrel.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.153.66`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'file_path contains \Microsoft\Teams\' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\Microsoft\Teams\\.as…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=ENG-WKS-262<br>`agent_ip`=10.42.153.66<br>… | file_path=C:\Users\j.mercer\AppData\Local\Temp\Microsoft\Teams\\.asar.bak fails 'file_path contains \Microsoft\Teams\' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.153.66`

