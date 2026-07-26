# Proof — 6c8d21c6-a761-4dc9-adfe-79f9b914ab1f

## Rule

- **Rule ID:** 6c8d21c6-a761-4dc9-adfe-79f9b914ab1f
- **Rule name:** LSA Password Filter DLL Registration (AN1303-A)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [] / [T1556.002]
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
| `target_object` | target_object regex .*\QSYSTEM\CurrentControlSet\Control\Lsa\Notification Packages\E$ | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages` |
| `registry_new_value` | registry_new_value not_in_list [scecli rassfm kdcsvc, scecli rassfm, scecli] | `C:\Program Files\Microsoft OneDrive\OneDrive.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SYSTEM…<br>`registry_new_value`=C:\Program Files\Microsoft OneDrive\OneDrive.exe<br>`hostname`=SEC-WKS-614<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.105.175`
- alert `d481a0a43ff992ec945ca8c999de2eac` on lane `entity_key` = `10.42.105.175`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDri…<br>`registry_new_value`=C:\Program Files\Microsoft OneDrive\OneDrive.exe<br>`hostname`=FIN-WKS-615<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.106.175`
- alert `7c534eacc3779cf1ec6c9947eb2edfa5` on lane `entity_key` = `10.42.106.175`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'registry_new_value not_in_list [scecli rassfm kdcsvc, scecli rassfm, scecli]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SYSTEM…<br>`registry_new_value`=scecli rassfm kdcsvc<br>`hostname`=SEC-WKS-614<br>… | registry_new_value=scecli rassfm kdcsvc fails 'registry_new_value not_in_list [scecli rassfm kdcsvc, scecli rassfm, scecli]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.105.175`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_object regex .*\QSYSTEM\CurrentControlSet\Control\Lsa\Notification Packages\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SYSTEM…<br>`registry_new_value`=C:\Program Files\Microsoft OneDrive\OneDrive.exe<br>`hostname`=SEC-WKS-614<br>… | target_object=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages.bak fails 'target_object regex .*\QSYSTEM\CurrentControlSet\Control\Lsa\Notification Packages\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.105.175`

