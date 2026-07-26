# Proof — AN0263

## Rule

- **Rule ID:** AN0263
- **Rule name:** AN0263 - Office Application Startup: Outlook Rules
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [persistence] / [T1137.005]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `target_object` | target_object contains \Software\Microsoft\Office\ AND target_object regex .*\Q\Outlook\Rules\E$ | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Software\Microsoft\Office\\Outlook\Rules` |
| `registry_event_type` | registry_event_type eq SetValue | `SetValue` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Softwa…<br>`registry_event_type`=SetValue<br>`hostname`=SEC-WKS-089<br>`agent_ip`=10.42.80.13<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.80.13`
- alert `13c499c5cbe7a4a00f77bde90e878819` on lane `entity_key` = `10.42.80.13`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDri…<br>`registry_event_type`=SetValue<br>`hostname`=OPS-WKS-088<br>`agent_ip`=10.42.79.13<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.79.13`
- alert `33683fa64bf17d3d9858061d247c28ab` on lane `entity_key` = `10.42.79.13`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'registry_event_type eq SetValue' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Softwa…<br>`registry_event_type`=SetValue.bak<br>`hostname`=SEC-WKS-089<br>`agent_ip`=10.42.80.13<br>… | registry_event_type=SetValue.bak fails 'registry_event_type eq SetValue' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.80.13`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_object regex .*\Q\Outlook\Rules\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Softwa…<br>`registry_event_type`=SetValue<br>`hostname`=SEC-WKS-089<br>`agent_ip`=10.42.80.13<br>… | target_object=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Software\Microsoft\Office\\Outlook\Rules.bak fails 'target_object regex .*\Q\Outlook\Rules\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.80.13`

