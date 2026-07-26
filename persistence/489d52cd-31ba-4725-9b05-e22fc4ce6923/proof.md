# Proof — 489d52cd-31ba-4725-9b05-e22fc4ce6923

## Rule

- **Rule ID:** 489d52cd-31ba-4725-9b05-e22fc4ce6923
- **Rule name:** Accessibility Features Registry Debugger Configuration (AN0094-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [persistence, privilege-escalation] / [T1546.008]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `target_object` | target_object regex .*\Q\Debugger\E$ AND target_object contains \Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Micros…<br>`hostname`=SEC-WKS-459<br>`agent_ip`=10.42.150.101<br>`event_id`=13<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.150.101`
- alert `698006bba53236975e9c0798c4f43040` on lane `entity_key` = `10.42.150.101`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDri…<br>`hostname`=FIN-WKS-460<br>`agent_ip`=10.42.151.101<br>`event_id`=13<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.151.101`
- alert `67edcc67b1fd04fc417dfbd992a77017` on lane `entity_key` = `10.42.151.101`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_object contains \Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Micros…<br>`hostname`=SEC-WKS-459<br>`agent_ip`=10.42.150.101<br>`event_id`=13<br>… | target_object=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger.bak fails 'target_object contains \Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.150.101`

## benign_2

**Expected alerts:** 0  
**Construction:** the field 'target_object' is absent entirely; an absent field is no-match for every operator, so the stage is never entered

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `hostname`=SEC-WKS-459<br>`agent_ip`=10.42.150.101<br>`event_id`=13<br>`image_path`=C:\Windows\System32\cmd.exe<br>… | carries no 'target_object' at all; evaluateCondition returns no-match for every operator on an absent field, so the stage gate rejects the event |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.150.101`

