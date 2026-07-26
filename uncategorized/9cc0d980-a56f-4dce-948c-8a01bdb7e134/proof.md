# Proof — 9cc0d980-a56f-4dce-948c-8a01bdb7e134

## Rule

- **Rule ID:** 9cc0d980-a56f-4dce-948c-8a01bdb7e134
- **Rule name:** Hybrid Identity Service Registry Tampering (AN0814-A)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [] / [T1556.007]
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
| `target_object` | target_object contains SOFTWARE\Microsoft\Microsoft Azure AD Connection Tool\ | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run SOFTWARE\Microsoft\Microsoft Azure AD Connection Tool\` |
| `image_path` | image_path not_regex .*\Q\AzureADConnect.exe\E$ AND image_path not_regex .*\Q\miiserver.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run SOFTWA…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=ENG-WKS-257<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.48.41`
- alert `844fd6babc35aa16b65706c6a6a34e21` on lane `entity_key` = `10.42.48.41`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDri…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=OPS-WKS-258<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.49.41`
- alert `65d2814e11b388f0a19d224c342ed86d` on lane `entity_key` = `10.42.49.41`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\miiserver.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run SOFTWA…<br>`image_path`=\miiserver.exe<br>`hostname`=ENG-WKS-257<br>… | image_path=\miiserver.exe fails 'image_path not_regex .*\Q\miiserver.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.48.41`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_object contains SOFTWARE\Microsoft\Microsoft Azure AD Connection Tool\' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDrive<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=ENG-WKS-257<br>… | target_object=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDrive fails 'target_object contains SOFTWARE\Microsoft\Microsoft Azure AD Connection Tool\' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.48.41`

