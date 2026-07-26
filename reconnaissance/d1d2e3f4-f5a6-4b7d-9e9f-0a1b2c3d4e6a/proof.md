# Proof — d1d2e3f4-f5a6-4b7d-9e9f-0a1b2c3d4e6a

## Rule

- **Rule ID:** d1d2e3f4-f5a6-4b7d-9e9f-0a1b2c3d4e6a
- **Rule name:** Phishing for Information from Compromised Internal Account (AN2073-Phishing-Internal)
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
| `sender_type` | sender_type eq internal | `internal` |
| `subject` | subject contains vpn config | `Quarterly report vpn config` |
| `sender` | sender not_regex .*\Q@phishing-training-platform.com\E$ | `j.mercer@corp.example.com` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `sender_type`=internal<br>`subject`=Quarterly report vpn config<br>`sender`=j.mercer@corp.example.com<br>`hostname`=FIN-WKS-200<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.191.206`
- alert `3abe34ea9f606a2f1f21b6dd69001a06` on lane `entity_key` = `10.42.191.206`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `sender_type`=internal<br>`subject`=C:\Windows\System32 antivirus config<br>`hostname`=SEC-WKS-199<br>`agent_ip`=10.42.190.206<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.190.206`
- alert `b7d234379438615e6fbb04e0956af88a` on lane `entity_key` = `10.42.190.206`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'subject contains vpn config' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `sender_type`=internal<br>`subject`=Quarterly report<br>`sender`=j.mercer@corp.example.com<br>`hostname`=FIN-WKS-200<br>… | subject=Quarterly report fails 'subject contains vpn config' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.191.206`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'sender_type eq internal' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `sender_type`=internal.bak<br>`subject`=Quarterly report vpn config<br>`sender`=j.mercer@corp.example.com<br>`hostname`=FIN-WKS-200<br>… | sender_type=internal.bak fails 'sender_type eq internal' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.191.206`

