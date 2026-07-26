# Proof — f1a2b3c4-e5f6-7a8b-9c0d-1e2f3a4b5d95

## Rule

- **Rule ID:** f1a2b3c4-e5f6-7a8b-9c0d-1e2f3a4b5d95
- **Rule name:** Privileged Account or Group Membership Manipulation (AN2114)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [persistence] / [T1098]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id in_list [4728, 4732, 4756] | `4728` |
| `target_user_name` | target_user_name in_list [Administrators, Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators] | `Administrators` |
| `subject_username` | subject_username not_regex .*\Q$\E$ | `SVC-BACKUP` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4728<br>`target_user_name`=Administrators<br>`subject_username`=SVC-BACKUP<br>`hostname`=FIN-WKS-290<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.81.38`
- alert `64be1dfb08f70ddb2dabbc5755f0b565` on lane `entity_key` = `10.42.81.38`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=4738<br>`user_account_control`=C:\Windows\System32 Don't Require Preauth<br>`subject_username`=SVC-BACKUP<br>`hostname`=SEC-WKS-289<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.80.38`
- alert `3ec6ebfbb052bd674a7f3a9a5a229b0a` on lane `entity_key` = `10.42.80.38`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'subject_username not_regex .*\Q$\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4728<br>`target_user_name`=Administrators<br>`subject_username`=$<br>`hostname`=FIN-WKS-290<br>… | subject_username=$ fails 'subject_username not_regex .*\Q$\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.81.38`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_user_name in_list [Administrators, Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=4728<br>`target_user_name`=Administrators.bak<br>`subject_username`=SVC-BACKUP<br>`hostname`=FIN-WKS-290<br>… | target_user_name=Administrators.bak fails 'target_user_name in_list [Administrators, Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.81.38`

