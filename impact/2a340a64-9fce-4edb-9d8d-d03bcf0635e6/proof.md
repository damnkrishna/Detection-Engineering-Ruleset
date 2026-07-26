# Proof — 2a340a64-9fce-4edb-9d8d-d03bcf0635e6

## Rule

- **Rule ID:** 2a340a64-9fce-4edb-9d8d-d03bcf0635e6
- **Rule name:** Logon Warning Banner Registry Modification (AN0662-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [impact] / [T1491]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id eq 13 | `13` |
| `target_object` | target_object regex .*\Q\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption\E$ | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption` |
| `image_path` | image_path not_regex .*\Q\svchost.exe\E$ | `C:\Windows\System32\cmd.exe` |
| `parent_image` | parent_image not_regex .*\Q\svchost.exe\E$ | `C:\Windows\explorer.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Micros…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`parent_image`=C:\Windows\explorer.exe<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.197.184`
- alert `36376aad6fcf03103325bfd2675adced` on lane `entity_key` = `10.42.197.184`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDri…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-205<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.196.184`
- alert `79b811e119027004daccb1560c76b6ee` on lane `entity_key` = `10.42.196.184`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\svchost.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Micros…<br>`image_path`=\svchost.exe<br>`parent_image`=C:\Windows\explorer.exe<br>… | image_path=\svchost.exe fails 'image_path not_regex .*\Q\svchost.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.197.184`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_object regex .*\Q\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Micros…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`parent_image`=C:\Windows\explorer.exe<br>… | target_object=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption.bak fails 'target_object regex .*\Q\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.197.184`

