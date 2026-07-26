# Proof — aca5e43c-0be4-43b3-a575-a5a46b7ab571

## Rule

- **Rule ID:** aca5e43c-0be4-43b3-a575-a5a46b7ab571
- **Rule name:** Trusted Relationship Abuse - Anomalous Third-Party Administrative Logon (AN1344)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [initial-access] / [T1199]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id eq 4624 | `4624` |
| `logon_type` | logon_type in_list [3, 10] | `3` |
| `target_user_name` | target_user_name contains vendor_ | `j.mercer vendor_` |
| `src_ip` | src_ip not_in_list [127.0.0.1, ::1] | `10.42.7.14` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4624<br>`logon_type`=3<br>`target_user_name`=j.mercer vendor_<br>`src_ip`=10.42.7.14<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 2 (1 cross-lane twin pair(s) merged by the post-correlation chain)
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `j.mercer vendor_`
- alert `a32f45d4b5a70d11d0e35bc307863720` on lane `entity_key` = `j.mercer vendor_`, match mode `THRESHOLD`, 1 matched event(s)
- alert `2cfcbf70a152fac015088089ab476ac1` on lane `src_ip` = `10.42.7.14`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=4624<br>`logon_type`=10<br>`domain`=C:\Windows\System32 vendor<br>`src_ip`=10.42.7.14<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 2 (1 cross-lane twin pair(s) merged by the post-correlation chain)
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.111.203`
- alert `d02a45d19a0645dac9687d6f37c995f4` on lane `entity_key` = `10.42.111.203`, match mode `THRESHOLD`, 1 matched event(s)
- alert `e9d689e9b431b9ab9651669f88bd9ae6` on lane `src_ip` = `10.42.7.14`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'src_ip not_in_list [127.0.0.1, ::1]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4624<br>`logon_type`=3<br>`target_user_name`=j.mercer vendor_<br>`src_ip`=127.0.0.1<br>… | src_ip=127.0.0.1 fails 'src_ip not_in_list [127.0.0.1, ::1]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `j.mercer vendor_`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_user_name contains vendor_' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4624<br>`logon_type`=3<br>`target_user_name`=j.mercer<br>`src_ip`=10.42.7.14<br>… | target_user_name=j.mercer fails 'target_user_name contains vendor_' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `j.mercer`

