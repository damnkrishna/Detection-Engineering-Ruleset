# Proof — c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f

## Rule

- **Rule ID:** c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f
- **Rule name:** External Port Scanning Detection (AN2070)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [zeek]
- **Replay wire:** zeek on topic `replay-events-zeek`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [reconnaissance] / [T1595]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `_raw` | _raw contains selection \| count(resp_p) by orig_h > 15 in 60s | `Nov 14 09:15:00 fin-wks-014 sshd[4812]: Accepted password for j.mercer selection \| count(resp_p) by orig_h > 15 in 60s` |
| `src_ip` | src_ip not_in_cidr 1.2.3.0/24 AND src_ip not_in_cidr 4.5.6.0/24 AND src_ip not_in_cidr 10.0.0.0/8 | `10.42.7.14` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `_raw`=Nov 14 09:15:00 fin-wks-014 sshd[4812]: Accepted password…<br>`src_ip`=10.42.7.14<br>`severity_id`=3<br>`event_uid`=golden\|c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f\|0\|603000<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 2
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `zeek`, lane key = `10.42.7.14`
- alert `22c55da7561d3de23ba1897ae5f32d41` on lane `entity_key` = `10.42.7.14`, match mode `THRESHOLD`, 1 matched event(s)
- alert `22c55da7561d3de23ba1897ae5f32d41` on lane `src_ip` = `10.42.7.14`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `_raw`=C:\Windows\System32 selection \| count(resp_p) by orig_h >…<br>`or user_agent`=C:\Users\j.mercer\AppData\Local\Temp<br>`src_ip`=10.42.7.14<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 2
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `zeek`, lane key = `10.42.7.14`
- alert `b41ab8778870cf5e143bfb4a2939d54f` on lane `entity_key` = `10.42.7.14`, match mode `THRESHOLD`, 1 matched event(s)
- alert `b41ab8778870cf5e143bfb4a2939d54f` on lane `src_ip` = `10.42.7.14`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for '_raw contains selection \| count(resp_p) by orig_h > 15 in 60s' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `_raw`=Nov 14 09:15:00 fin-wks-014 sshd[4812]: Accepted password…<br>`src_ip`=10.42.7.14<br>`severity_id`=3<br>`event_uid`=golden\|c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f\|0\|447100<br>… | _raw=Nov 14 09:15:00 fin-wks-014 sshd[4812]: Accepted password for j.mercer fails '_raw contains selection \| count(resp_p) by orig_h > 15 in 60s' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `zeek`, lane key = `10.42.7.14`

## benign_2

**Expected alerts:** 0  
**Construction:** the field 'src_ip' is absent entirely; an absent field is no-match for every operator, so the stage is never entered

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `_raw`=Nov 14 09:15:00 fin-wks-014 sshd[4812]: Accepted password…<br>`severity_id`=3<br>`event_uid`=golden\|c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f\|0\|447100<br>`proto`=tcp<br>… | carries no 'src_ip' at all; evaluateCondition returns no-match for every operator on an absent field, so the stage gate rejects the event |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `zeek`, lane key = `unknown`

