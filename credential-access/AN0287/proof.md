# Proof — AN0287

## Rule

- **Rule ID:** AN0287
- **Rule name:** Suspicious LSA Authentication Package Modification (AN0287)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [credential-access, defense-evasion, persistence] / [T1556, T1556.002]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `target_object` | target_object contains \CurrentControlSet\Control\Lsa\Authentication Packages | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\CurrentControlSet\Control\Lsa\Authentication Packages` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Curren…<br>`hostname`=OPS-WKS-563<br>`agent_ip`=10.42.54.96<br>`event_id`=13<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.54.96`
- alert `a6d81dd8462fe9ff6191818b6af61498` on lane `entity_key` = `10.42.54.96`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDri…<br>`hostname`=ENG-WKS-562<br>`agent_ip`=10.42.53.96<br>`event_id`=13<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.53.96`
- alert `df0315b778cfea65d6e5207b98aac65a` on lane `entity_key` = `10.42.53.96`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_object contains \CurrentControlSet\Control\Lsa\Authentication Packages' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Curren…<br>`hostname`=OPS-WKS-563<br>`agent_ip`=10.42.54.96<br>`event_id`=13<br>… | target_object=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\CurrentControlSet\Control\Lsa\contoso-Authentication Packages fails 'target_object contains \CurrentControlSet\Control\Lsa\Authentication Packages' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.54.96`

## benign_2

**Expected alerts:** 0  
**Construction:** the field 'target_object' is absent entirely; an absent field is no-match for every operator, so the stage is never entered

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `hostname`=OPS-WKS-563<br>`agent_ip`=10.42.54.96<br>`event_id`=13<br>`image_path`=C:\Windows\System32\cmd.exe<br>… | carries no 'target_object' at all; evaluateCondition returns no-match for every operator on an absent field, so the stage gate rejects the event |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.54.96`

