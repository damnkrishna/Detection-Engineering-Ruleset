# Proof — 28d70650-3536-4fe8-a1db-14e242c9665a

## Rule

- **Rule ID:** 28d70650-3536-4fe8-a1db-14e242c9665a
- **Rule name:** LSA Security Packages Registry Modification (AN0757-C)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [] / [T1556.001]
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
| `target_object` | target_object contains SYSTEM\CurrentControlSet\Control\Lsa\Security Packages | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` |
| `registry_new_value` | registry_new_value not_in_list [kerberos msv1_0 schannel wdigest tspkg pku2u credssp, kerberos msv1_0 schannel wdigest tspkg pku2u, kerberos msv1_0 schannel wdigest tspkg credssp] | `C:\Program Files\Microsoft OneDrive\OneDrive.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run SYSTEM…<br>`registry_new_value`=C:\Program Files\Microsoft OneDrive\OneDrive.exe<br>`hostname`=OPS-WKS-443<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.34.191`
- alert `a4da17677cfa8959046c7326148a9646` on lane `entity_key` = `10.42.34.191`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDri…<br>`registry_new_value`=C:\Program Files\Microsoft OneDrive\OneDrive.exe<br>`hostname`=SEC-WKS-444<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.35.191`
- alert `713db9312dcc8af80eb34041bba5b5b7` on lane `entity_key` = `10.42.35.191`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'registry_new_value not_in_list [kerberos msv1_0 schannel wdigest tspkg pku2u credssp, kerberos msv1_0 schannel wdigest tspkg pku2u, kerberos msv1_0 schannel wdigest tspkg credssp]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run SYSTEM…<br>`registry_new_value`=kerberos msv1_0 schannel wdigest tspkg pku2u credssp<br>`hostname`=OPS-WKS-443<br>… | registry_new_value=kerberos msv1_0 schannel wdigest tspkg pku2u credssp fails 'registry_new_value not_in_list [kerberos msv1_0 schannel wdigest tspkg pku2u credssp, kerberos msv1_0 schannel wdigest tspkg pku2u, kerberos msv1_0 schannel wdigest tspkg credssp]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.34.191`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_object contains SYSTEM\CurrentControlSet\Control\Lsa\Security Packages' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run SYSTEM…<br>`registry_new_value`=C:\Program Files\Microsoft OneDrive\OneDrive.exe<br>`hostname`=OPS-WKS-443<br>… | target_object=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run SYSTEM\CurrentControlSet\Control\Lsa\contoso-Security Packages fails 'target_object contains SYSTEM\CurrentControlSet\Control\Lsa\Security Packages' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.34.191`

