# Proof — AN0123

## Rule

- **Rule ID:** AN0123
- **Rule name:** AN0123 - Software Extensions: Browser Extensions
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [persistence] / [T1176.001]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `registry_event_type` | registry_event_type eq SetValue | `SetValue` |
| `target_object` | target_object contains \Software\Policies\Google\Chrome\ExtensionInstallForcelist | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Software\Policies\Google\Chrome\ExtensionInstallForcelist` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `registry_event_type`=SetValue<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Softwa…<br>`hostname`=SEC-WKS-574<br>`agent_ip`=10.42.165.26<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.165.26`
- alert `7ceefa9b6b6d66834efeba78d447a128` on lane `entity_key` = `10.42.165.26`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `registry_event_type`=SetValue<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDri…<br>`hostname`=OPS-WKS-573<br>`agent_ip`=10.42.164.26<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.164.26`
- alert `06140ba985977d27abb94cc58bfcb854` on lane `entity_key` = `10.42.164.26`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_object contains \Software\Policies\Google\Chrome\ExtensionInstallForcelist' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `registry_event_type`=SetValue<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Softwa…<br>`hostname`=SEC-WKS-574<br>`agent_ip`=10.42.165.26<br>… | target_object=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Software\Policies\Google\Chrome\contoso-ExtensionInstallForcelist fails 'target_object contains \Software\Policies\Google\Chrome\ExtensionInstallForcelist' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.165.26`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'registry_event_type eq SetValue' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `registry_event_type`=SetValue.bak<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Softwa…<br>`hostname`=SEC-WKS-574<br>`agent_ip`=10.42.165.26<br>… | registry_event_type=SetValue.bak fails 'registry_event_type eq SetValue' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.165.26`

