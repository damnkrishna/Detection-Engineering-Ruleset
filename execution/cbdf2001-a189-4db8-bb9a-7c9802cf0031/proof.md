# Proof — cbdf2001-a189-4db8-bb9a-7c9802cf0031

## Rule

- **Rule ID:** cbdf2001-a189-4db8-bb9a-7c9802cf0031
- **Rule name:** Process Access Handle for Direct Syscalls (AN1465-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [execution] / [T1106]
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
| `granted_access` | granted_access in_list [0x1F0FFF, 0x1F1FFF, 0x1410, 0x1F3FFF] | `0x1F0FFF` |
| `source_image` | source_image contains \Users\ AND source_image not_regex .*\Q\chrome.exe\E$ AND source_image not_regex .*\Q\firefox.exe\E$ AND source_image not_regex .*\Q\msedge.exe\E$ AND source_image not_regex .*\Q\MsMpEng.exe\E$ | `C:\Windows\System32\Users\` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=10<br>`granted_access`=0x1F0FFF<br>`source_image`=C:\Windows\System32\Users\<br>`hostname`=SEC-WKS-194<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.185.64`
- alert `0a9ecc3837c3f5c6b45d1305a3fd2f48` on lane `entity_key` = `10.42.185.64`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=10<br>`granted_access`=0x1F1FFF<br>`source_image`=C:\Windows\System32\cmd.exe\Temp\<br>`hostname`=FIN-WKS-195<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.186.64`
- alert `4cbdcd81d7abf445c3926fdae91a8ec2` on lane `entity_key` = `10.42.186.64`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'source_image not_regex .*\Q\MsMpEng.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=10<br>`granted_access`=0x1F0FFF<br>`source_image`=\MsMpEng.exe<br>`hostname`=SEC-WKS-194<br>… | source_image=\MsMpEng.exe fails 'source_image not_regex .*\Q\MsMpEng.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.185.64`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'granted_access in_list [0x1F0FFF, 0x1F1FFF, 0x1410, 0x1F3FFF]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=10<br>`granted_access`=0x1F0FFF.bak<br>`source_image`=C:\Windows\System32\Users\<br>`hostname`=SEC-WKS-194<br>… | granted_access=0x1F0FFF.bak fails 'granted_access in_list [0x1F0FFF, 0x1F1FFF, 0x1410, 0x1F3FFF]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.185.64`

