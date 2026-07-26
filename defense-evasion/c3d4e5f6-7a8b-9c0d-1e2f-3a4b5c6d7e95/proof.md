# Proof — c3d4e5f6-7a8b-9c0d-1e2f-3a4b5c6d7e95

## Rule

- **Rule ID:** c3d4e5f6-7a8b-9c0d-1e2f-3a4b5c6d7e95
- **Rule name:** Anomalous Handle Access to System Process for Exploitation or Stealth (AN2117)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [defense-evasion] / [T1211]
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
| `granted_access` | granted_access in_list [0x1F0FFF, 0x1f0fff, 0x1010, 0x1410, 0x1438, 0x143a] | `0x1F0FFF` |
| `target_image` | target_image regex .*\Q\lsass.exe\E$ | `C:\Windows\System32\lsass.exe` |
| `source_image` | source_image not_regex .*\Q\taskmgr.exe\E$ AND source_image not_regex .*\Q\resmon.exe\E$ AND source_image not_regex .*\Q\processhacker.exe\E$ AND source_image not_regex .*\Q\msiexec.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=10<br>`granted_access`=0x1F0FFF<br>`target_image`=C:\Windows\System32\lsass.exe<br>`source_image`=C:\Windows\System32\cmd.exe<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.98.64`
- alert `b67100fecd87bd5225abe18cf0cdc800` on lane `entity_key` = `10.42.98.64`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=10<br>`granted_access`=0x1f0fff<br>`target_image`=C:\Windows\System32\lsass.exe\svchost.exe<br>`source_image`=C:\Windows\System32\cmd.exe<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.99.64`
- alert `37ea244e7dd788c0674d5609e2c8c299` on lane `entity_key` = `10.42.99.64`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'source_image not_regex .*\Q\msiexec.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=10<br>`granted_access`=0x1F0FFF<br>`target_image`=C:\Windows\System32\lsass.exe<br>`source_image`=\msiexec.exe<br>… | source_image=\msiexec.exe fails 'source_image not_regex .*\Q\msiexec.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.98.64`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_image regex .*\Q\lsass.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=10<br>`granted_access`=0x1F0FFF<br>`target_image`=C:\Windows\System32\lsass.exe.bak<br>`source_image`=C:\Windows\System32\cmd.exe<br>… | target_image=C:\Windows\System32\lsass.exe.bak fails 'target_image regex .*\Q\lsass.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.98.64`

