# Proof — 1d799b7b-8c5f-45bc-9a82-9c054e7d86ee

## Rule

- **Rule ID:** 1d799b7b-8c5f-45bc-9a82-9c054e7d86ee
- **Rule name:** Remote Thread Creation in Transaction Application Processes (AN1097-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [impact] / [T1565.003]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id eq 8 | `8` |
| `target_image` | target_image regex .*\Q\pos.exe\E$ | `C:\Windows\System32\pos.exe` |
| `source_image` | source_image not_regex .*\Q\system32\svchost.exe\E$ AND source_image not_regex .*\Q\system32\csrss.exe\E$ AND source_image not_regex .*\Q\system32\lsass.exe\E$ AND source_image not_regex .*\Q\system32\winlogon.exe\E$ AND source_image not_regex .*\Q\MsMpEng.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=8<br>`target_image`=C:\Windows\System32\pos.exe<br>`source_image`=C:\Windows\System32\cmd.exe<br>`hostname`=SEC-WKS-739<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.30.131`
- alert `f1b3c47621394bfa0437f7b679c13ec2` on lane `entity_key` = `10.42.30.131`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=8<br>`target_image`=C:\Windows\System32\lsass.exe\retail.exe<br>`source_image`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-740<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.31.131`
- alert `6240bbef221f5a45826c226831765b35` on lane `entity_key` = `10.42.31.131`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'source_image not_regex .*\Q\MsMpEng.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=8<br>`target_image`=C:\Windows\System32\pos.exe<br>`source_image`=\MsMpEng.exe<br>`hostname`=SEC-WKS-739<br>… | source_image=\MsMpEng.exe fails 'source_image not_regex .*\Q\MsMpEng.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.30.131`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_image regex .*\Q\pos.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=8<br>`target_image`=C:\Windows\System32\pos.exe.bak<br>`source_image`=C:\Windows\System32\cmd.exe<br>`hostname`=SEC-WKS-739<br>… | target_image=C:\Windows\System32\pos.exe.bak fails 'target_image regex .*\Q\pos.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.30.131`

