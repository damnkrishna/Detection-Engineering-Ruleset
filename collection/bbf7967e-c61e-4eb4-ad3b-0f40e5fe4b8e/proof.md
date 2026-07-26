# Proof — bbf7967e-c61e-4eb4-ad3b-0f40e5fe4b8e

## Rule

- **Rule ID:** bbf7967e-c61e-4eb4-ad3b-0f40e5fe4b8e
- **Rule name:** Web Server Root Folder File Creation (AN1321)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [collection] / [T1056.003]
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
| `file_path` | file_path contains \inetpub\wwwroot\ AND file_path regex .*\Q.php\E$ | `C:\Users\j.mercer\AppData\Local\Temp\inetpub\wwwroot\.php` |
| `image_path` | image_path not_regex .*\Q\trustedinstaller.exe\E$ AND image_path not_regex .*\Q\msiexec.exe\E$ AND image_path not_regex .*\Q\tiworker.exe\E$ | `C:\Windows\System32\cmd.exe` |
| `username` | username not_in_list [NT AUTHORITY\SYSTEM, NT AUTHORITY\NETWORK SERVICE] | `CORP\j.mercer` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\inetpub\wwwroot\.php<br>`image_path`=C:\Windows\System32\cmd.exe<br>`username`=CORP\j.mercer<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `CORP\j.mercer`
- alert `a5355f2e7334625f3804e3a75f604f2b` on lane `entity_key` = `CORP\j.mercer`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp\apache\ht…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=HR-WKS-406<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.97.104`
- alert `4c59d4bf7d7978a731b12cb74b2fb414` on lane `entity_key` = `10.42.97.104`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\tiworker.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\inetpub\wwwroot\.php<br>`image_path`=\tiworker.exe<br>`username`=CORP\j.mercer<br>… | image_path=\tiworker.exe fails 'image_path not_regex .*\Q\tiworker.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `CORP\j.mercer`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'file_path regex .*\Q.php\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\inetpub\wwwroot\.php…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`username`=CORP\j.mercer<br>… | file_path=C:\Users\j.mercer\AppData\Local\Temp\inetpub\wwwroot\.php.bak fails 'file_path regex .*\Q.php\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `CORP\j.mercer`

