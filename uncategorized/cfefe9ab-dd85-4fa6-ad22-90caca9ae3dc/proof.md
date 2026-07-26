# Proof — cfefe9ab-dd85-4fa6-ad22-90caca9ae3dc

## Rule

- **Rule ID:** cfefe9ab-dd85-4fa6-ad22-90caca9ae3dc
- **Rule name:** Active Directory Trust Object Modification (AN1259-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [] / [T1484.002]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id eq 4662 | `4662` |
| `object_type` | object_type contains 19195a5b-6da0-11d0-afd3-00c04fd930c9 | `File 19195a5b-6da0-11d0-afd3-00c04fd930c9` |
| `object_dn` | object_dn contains CN=System | `C:\Windows\System32 CN=System` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4662<br>`object_type`=File 19195a5b-6da0-11d0-afd3-00c04fd930c9<br>`object_dn`=C:\Windows\System32 CN=System<br>`hostname`=OPS-WKS-093<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.84.181`
- alert `b39891eaff0602593e4fa38eff32a534` on lane `entity_key` = `10.42.84.181`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=5136<br>`object_class`=C:\Users\j.mercer\AppData\Local\Temp trustedDomain<br>`object_dn`=C:\Users\j.mercer\AppData\Local\Temp CN=System<br>`hostname`=ENG-WKS-092<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.83.181`
- alert `6643ec0c3c2352ef6ef950fa27221aa1` on lane `entity_key` = `10.42.83.181`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'object_dn contains CN=System' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4662<br>`object_type`=File 19195a5b-6da0-11d0-afd3-00c04fd930c9<br>`object_dn`=contoso-reporting<br>`hostname`=OPS-WKS-093<br>… | object_dn=contoso-reporting fails 'object_dn contains CN=System' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.84.181`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'object_type contains 19195a5b-6da0-11d0-afd3-00c04fd930c9' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4662<br>`object_type`=File<br>`object_dn`=C:\Windows\System32 CN=System<br>`hostname`=OPS-WKS-093<br>… | object_type=File fails 'object_type contains 19195a5b-6da0-11d0-afd3-00c04fd930c9' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.84.181`

