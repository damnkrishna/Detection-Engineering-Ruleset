# Proof — cbdf2001-a189-4db8-bb9a-7c9802cf0027

## Rule

- **Rule ID:** cbdf2001-a189-4db8-bb9a-7c9802cf0027
- **Rule name:** Registry Modification Enabling DDE Execution (AN1393-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [execution] / [T1559.002]
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
| `registry_new_value` | registry_new_value in_list [DWORD (0x00000001), 1] | `DWORD (0x00000001)` |
| `target_object` | target_object contains \Word\Options\AllowDDE | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Word\Options\AllowDDE` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`registry_new_value`=DWORD (0x00000001)<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Word\O…<br>`hostname`=SEC-WKS-469<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.160.144`
- alert `e8618782ed489766ece781dfc55aacdd` on lane `entity_key` = `10.42.160.144`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=13<br>`registry_new_value`=1<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDri…<br>`hostname`=FIN-WKS-470<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.161.144`
- alert `e94882f0646484e27efeca878c6de586` on lane `entity_key` = `10.42.161.144`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_object contains \Word\Options\AllowDDE' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`registry_new_value`=DWORD (0x00000001)<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Word\O…<br>`hostname`=SEC-WKS-469<br>… | target_object=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Word\Options\contoso-AllowDDE fails 'target_object contains \Word\Options\AllowDDE' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.160.144`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'registry_new_value in_list [DWORD (0x00000001), 1]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`registry_new_value`=DWORD (0x00000001).bak<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Word\O…<br>`hostname`=SEC-WKS-469<br>… | registry_new_value=DWORD (0x00000001).bak fails 'registry_new_value in_list [DWORD (0x00000001), 1]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.160.144`

