# Proof — d1d2e3f4-f5a6-4b7d-9e9f-0a1b2c3d4e5f

## Rule

- **Rule ID:** d1d2e3f4-f5a6-4b7d-9e9f-0a1b2c3d4e5f
- **Rule name:** Phishing for Information (AN2073)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** []
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [reconnaissance] / [T1598]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `sender_type` | sender_type eq external | `external` |
| `subject` | subject contains vpn config | `Quarterly report vpn config` |
| `sender` | sender not_regex .*\Q@authorized-vendor.com\E$ AND sender not_regex .*\Q@internal-domain.com\E$ | `j.mercer@corp.example.com` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `sender_type`=external<br>`subject`=Quarterly report vpn config<br>`sender`=j.mercer@corp.example.com<br>`hostname`=HR-WKS-886<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.177.131`
- alert `86699abb0b59324ca99c5b49196fdb56` on lane `entity_key` = `10.42.177.131`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `sender_type`=external<br>`subject`=C:\Windows\System32 antivirus config<br>`sender`=j.mercer@corp.example.com<br>`hostname`=FIN-WKS-885<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.176.131`
- alert `262e888e212fce63e89468858db82083` on lane `entity_key` = `10.42.176.131`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'sender not_regex .*\Q@internal-domain.com\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `sender_type`=external<br>`subject`=Quarterly report vpn config<br>`sender`=@internal-domain.com<br>`hostname`=HR-WKS-886<br>… | sender=@internal-domain.com fails 'sender not_regex .*\Q@internal-domain.com\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.177.131`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'subject contains vpn config' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `sender_type`=external<br>`subject`=Quarterly report<br>`sender`=j.mercer@corp.example.com<br>`hostname`=HR-WKS-886<br>… | subject=Quarterly report fails 'subject contains vpn config' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.177.131`

