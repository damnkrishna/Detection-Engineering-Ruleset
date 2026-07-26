# Proof — f1a2b3c4-e5f6-7a8b-9c0d-1e2f3a4b5d98

## Rule

- **Rule ID:** f1a2b3c4-e5f6-7a8b-9c0d-1e2f3a4b5d98
- **Rule name:** Custom Security Support Provider or LSA Package Registration (AN2115)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [credential-access] / [T1111]
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
| `target_object` | target_object contains \System\CurrentControlSet\Control\Lsa\Security Packages | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\System\CurrentControlSet\Control\Lsa\Security Packages` |
| `parent_image` | parent_image not_regex .*\Q\msiexec.exe\E$ AND parent_image not_regex .*\Q\setup.exe\E$ | `C:\Windows\explorer.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\System…<br>`parent_image`=C:\Windows\explorer.exe<br>`hostname`=ENG-WKS-107<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.198.23`
- alert `00da820e8b8bb036daa35141bc81b886` on lane `entity_key` = `10.42.198.23`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDri…<br>`parent_image`=C:\Windows\explorer.exe<br>`hostname`=HR-WKS-106<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.197.23`
- alert `0a3250a8e77f1e150536970a159636a0` on lane `entity_key` = `10.42.197.23`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'parent_image not_regex .*\Q\setup.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\System…<br>`parent_image`=\setup.exe<br>`hostname`=ENG-WKS-107<br>… | parent_image=\setup.exe fails 'parent_image not_regex .*\Q\setup.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.198.23`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_object contains \System\CurrentControlSet\Control\Lsa\Security Packages' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=13<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\System…<br>`parent_image`=C:\Windows\explorer.exe<br>`hostname`=ENG-WKS-107<br>… | target_object=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\System\CurrentControlSet\Control\Lsa\contoso-Security Packages fails 'target_object contains \System\CurrentControlSet\Control\Lsa\Security Packages' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.198.23`

