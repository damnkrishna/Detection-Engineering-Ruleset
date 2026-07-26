# Proof — 7a482b35-be45-4dca-81fd-75cad5bab2cf

## Rule

- **Rule ID:** 7a482b35-be45-4dca-81fd-75cad5bab2cf
- **Rule name:** Lateral Movement - NTLM Pass the Hash Detection (AN1144)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [lateral-movement] / [T1550.002]
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
| `logon_type` | logon_type eq 3 | `3` |
| `lm_package_name` | lm_package_name starts_with NTLM | `NTLM` |
| `key_length` | key_length eq 0 | `0` |
| `src_ip` | src_ip not_in_list [127.0.0.1, ::1] | `10.42.7.14` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4624<br>`logon_type`=3<br>`lm_package_name`=NTLM<br>`key_length`=0<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 2 (1 cross-lane twin pair(s) merged by the post-correlation chain)
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.184.115`
- alert `ed22f5d3cdf7c41307c79641fe064353` on lane `entity_key` = `10.42.184.115`, match mode `THRESHOLD`, 1 matched event(s)
- alert `9a86401e5a7e5a2e8d52ecfc2e51a6df` on lane `src_ip` = `10.42.7.14`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=4624<br>`logon_type`=3<br>`lm_package_name`=NTLM<br>`key_length`=0<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 2 (1 cross-lane twin pair(s) merged by the post-correlation chain)
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.185.115`
- alert `caab9f9aecf3776cf2d5ec5619759ca0` on lane `entity_key` = `10.42.185.115`, match mode `THRESHOLD`, 1 matched event(s)
- alert `c1804726b6d7d5ab5f024bccb2b76db8` on lane `src_ip` = `10.42.7.14`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'src_ip not_in_list [127.0.0.1, ::1]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4624<br>`logon_type`=3<br>`lm_package_name`=NTLM<br>`key_length`=0<br>… | src_ip=127.0.0.1 fails 'src_ip not_in_list [127.0.0.1, ::1]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.184.115`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'key_length eq 0' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4624<br>`logon_type`=3<br>`lm_package_name`=NTLM<br>`key_length`=0.bak<br>… | key_length=0.bak fails 'key_length eq 0' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.184.115`

