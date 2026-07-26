# Proof — 4bfe6f18-0d3e-4873-8abf-2cb7107ef6c4

## Rule

- **Rule ID:** 4bfe6f18-0d3e-4873-8abf-2cb7107ef6c4
- **Rule name:** Logon Process Memory Access (AN0389-A)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [collection] / [T1056.004]
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
| `granted_access` | granted_access in_list [0x1F3FFF, 0x1F0FFF, 0x1010, 0x1410, 0x1438] | `0x1F3FFF` |
| `target_image` | target_image regex .*\Q\logonui.exe\E$ | `C:\Windows\System32\logonui.exe` |
| `source_image` | source_image not_regex .*\Q\services.exe\E$ AND source_image not_regex .*\Q\wininit.exe\E$ AND source_image not_regex .*\Q\csrss.exe\E$ AND source_image not_regex .*\Q\winlogon.exe\E$ AND source_image not_regex .*\Q\MsMpEng.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=10<br>`granted_access`=0x1F3FFF<br>`target_image`=C:\Windows\System32\logonui.exe<br>`source_image`=C:\Windows\System32\cmd.exe<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.27.13`
- alert `92091fd39f975eb8d3076dd77f0764f2` on lane `entity_key` = `10.42.27.13`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=10<br>`granted_access`=0x1F0FFF<br>`target_image`=C:\Windows\System32\lsass.exe<br>`source_image`=C:\Windows\System32\cmd.exe<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.28.13`
- alert `9147eb7215f5e02a2e6b324584e495c9` on lane `entity_key` = `10.42.28.13`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'source_image not_regex .*\Q\MsMpEng.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=10<br>`granted_access`=0x1F3FFF<br>`target_image`=C:\Windows\System32\logonui.exe<br>`source_image`=\MsMpEng.exe<br>… | source_image=\MsMpEng.exe fails 'source_image not_regex .*\Q\MsMpEng.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.27.13`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_image regex .*\Q\logonui.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=10<br>`granted_access`=0x1F3FFF<br>`target_image`=C:\Windows\System32\logonui.exe.bak<br>`source_image`=C:\Windows\System32\cmd.exe<br>… | target_image=C:\Windows\System32\logonui.exe.bak fails 'target_image regex .*\Q\logonui.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.27.13`

