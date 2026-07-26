# Proof — 33b5dfcd-fce4-48f1-9b11-70c583e472e8

## Rule

- **Rule ID:** 33b5dfcd-fce4-48f1-9b11-70c583e472e8
- **Rule name:** Rogue Domain Controller - Kerberos DRS SPN Request by Non-DC Host (AN0770)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [defense-evasion] / [T1207]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id eq 4769 | `4769` |
| `service_name` | service_name contains E3514235-4B06-11D1-AB04-00C04FC2DCD2 | `WinDefendUpd E3514235-4B06-11D1-AB04-00C04FC2DCD2` |
| `target_user_name` | target_user_name not_regex .*\Q$\E$ | `j.mercer` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4769<br>`service_name`=WinDefendUpd E3514235-4B06-11D1-AB04-00C04FC2DCD2<br>`target_user_name`=j.mercer<br>`hostname`=OPS-WKS-518<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; operates on a staging-directory path, which is what marks the process suspicious and backs the rule's high-rarity ATT&CK claim [T1207] |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.9.13`
- alert `5c34c3ebc0a2fa91a1963a01c3735f8b` on lane `entity_key` = `10.42.9.13`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=4769<br>`service_name`=C:\Windows\System32 E3514235-4B06-11D1-AB04-00C04FC2DCD2<br>`target_user_name`=j.mercer<br>`hostname`=ENG-WKS-517<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; operates on a staging-directory path, which is what marks the process suspicious and backs the rule's high-rarity ATT&CK claim [T1207] |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.8.13`
- alert `74d790d2c65d6d201301195b1e0f2b67` on lane `entity_key` = `10.42.8.13`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_user_name not_regex .*\Q$\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4769<br>`service_name`=WinDefendUpd E3514235-4B06-11D1-AB04-00C04FC2DCD2<br>`target_user_name`=$<br>`hostname`=OPS-WKS-518<br>… | target_user_name=$ fails 'target_user_name not_regex .*\Q$\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.9.13`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'service_name contains E3514235-4B06-11D1-AB04-00C04FC2DCD2' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4769<br>`service_name`=WinDefendUpd<br>`target_user_name`=j.mercer<br>`hostname`=OPS-WKS-518<br>… | service_name=WinDefendUpd fails 'service_name contains E3514235-4B06-11D1-AB04-00C04FC2DCD2' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.9.13`

