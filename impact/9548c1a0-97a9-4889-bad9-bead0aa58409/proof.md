# Proof — 9548c1a0-97a9-4889-bad9-bead0aa58409

## Rule

- **Rule ID:** 9548c1a0-97a9-4889-bad9-bead0aa58409
- **Rule name:** Transaction Database File Manipulation (AN1361-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [impact] / [T1657]
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
| `file_path` | file_path contains \pos_db\ AND file_path regex .*\Q.mdf\E$ | `C:\Users\j.mercer\AppData\Local\Temp\pos_db\.mdf` |
| `image_path` | image_path not_regex .*\Q\sqlserver.exe\E$ AND image_path not_regex .*\Q\mysqld.exe\E$ AND image_path not_regex .*\Q\postgres.exe\E$ AND image_path not_regex .*\Q\pos_service.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\pos_db\.mdf<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=ENG-WKS-817<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.108.98`
- alert `0c866eaa23b32707305947e60c56cbbd` on lane `entity_key` = `10.42.108.98`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp\retail_sa…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=HR-WKS-816<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.107.98`
- alert `b24b6ea9df5e36e45745f39de7dfa14a` on lane `entity_key` = `10.42.107.98`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\pos_service.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\pos_db\.mdf<br>`image_path`=\pos_service.exe<br>`hostname`=ENG-WKS-817<br>… | image_path=\pos_service.exe fails 'image_path not_regex .*\Q\pos_service.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.108.98`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'file_path regex .*\Q.mdf\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\pos_db\.mdf.bak<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=ENG-WKS-817<br>… | file_path=C:\Users\j.mercer\AppData\Local\Temp\pos_db\.mdf.bak fails 'file_path regex .*\Q.mdf\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.108.98`

