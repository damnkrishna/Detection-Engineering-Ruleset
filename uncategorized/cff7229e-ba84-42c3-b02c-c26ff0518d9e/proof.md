# Proof — cff7229e-ba84-42c3-b02c-c26ff0518d9e

## Rule

- **Rule ID:** cff7229e-ba84-42c3-b02c-c26ff0518d9e
- **Rule name:** LSASS Process Access on Domain Controller (AN0757-A)
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
| `event_id` | event_id eq 10 | `10` |
| `target_image` | target_image regex .*\Q\lsass.exe\E$ | `C:\Windows\System32\lsass.exe` |
| `granted_access` | granted_access in_list [0x1F3FFF, 0x1F0FFF, 0x1010, 0x1410, 0x1438] | `0x1F3FFF` |
| `source_image` | source_image not_regex .*\Q\services.exe\E$ AND source_image not_regex .*\Q\wininit.exe\E$ AND source_image not_regex .*\Q\csrss.exe\E$ AND source_image not_regex .*\Q\MsMpEng.exe\E$ AND source_image not_regex .*\Q\winlogon.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=10<br>`target_image`=C:\Windows\System32\lsass.exe<br>`granted_access`=0x1F3FFF<br>`source_image`=C:\Windows\System32\cmd.exe<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.179.192`
- alert `dcba4e3f78b67333b8b88222c4db6cf5` on lane `entity_key` = `10.42.179.192`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=10<br>`target_image`=C:\Windows\System32\lsass.exe<br>`granted_access`=0x1F0FFF<br>`source_image`=C:\Windows\System32\cmd.exe<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.178.192`
- alert `14a559d972480f20fc405ab9202517d7` on lane `entity_key` = `10.42.178.192`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'source_image not_regex .*\Q\winlogon.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=10<br>`target_image`=C:\Windows\System32\lsass.exe<br>`granted_access`=0x1F3FFF<br>`source_image`=\winlogon.exe<br>… | source_image=\winlogon.exe fails 'source_image not_regex .*\Q\winlogon.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.179.192`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'granted_access in_list [0x1F3FFF, 0x1F0FFF, 0x1010, 0x1410, 0x1438]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=10<br>`target_image`=C:\Windows\System32\lsass.exe<br>`granted_access`=0x1F3FFF.bak<br>`source_image`=C:\Windows\System32\cmd.exe<br>… | granted_access=0x1F3FFF.bak fails 'granted_access in_list [0x1F3FFF, 0x1F0FFF, 0x1010, 0x1410, 0x1438]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.179.192`

