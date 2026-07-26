# Proof — f1a2b3c4-e5f6-7a8b-9c0d-1e2f3a4b5c90

## Rule

- **Rule ID:** f1a2b3c4-e5f6-7a8b-9c0d-1e2f3a4b5c90
- **Rule name:** User Logon Initialization Script Registry Modification (AN2112)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [persistence] / [T1037]
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
| `target_object` | target_object contains \Environment\UserInitMprLoopbackScript | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Environment\UserInitMprLoopbackScript` |
| `registry_new_value` | registry_new_value neq C:\Windows\system32\userinit.exe, | `C:\Program Files\Microsoft OneDrive\OneDrive.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Enviro…<br>`registry_new_value`=C:\Program Files\Microsoft OneDrive\OneDrive.exe<br>`hostname`=HR-WKS-716<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.7.80`
- alert `112c5b23ef120392e2a08c6db1dd5fb3` on lane `entity_key` = `10.42.7.80`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDri…<br>`registry_new_value`=C:\Program Files\Microsoft OneDrive\OneDrive.exe<br>`hostname`=FIN-WKS-715<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.6.80`
- alert `4db1247fcecbc4f9821454ede5b704b5` on lane `entity_key` = `10.42.6.80`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'registry_new_value neq C:\Windows\system32\userinit.exe,' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Enviro…<br>`registry_new_value`=C:\Windows\system32\userinit.exe,<br>`hostname`=HR-WKS-716<br>… | registry_new_value=C:\Windows\system32\userinit.exe, fails 'registry_new_value neq C:\Windows\system32\userinit.exe,' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.7.80`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_object contains \Environment\UserInitMprLoopbackScript' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Enviro…<br>`registry_new_value`=C:\Program Files\Microsoft OneDrive\OneDrive.exe<br>`hostname`=HR-WKS-716<br>… | target_object=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Environment\contoso-UserInitMprLoopbackScript fails 'target_object contains \Environment\UserInitMprLoopbackScript' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.7.80`

