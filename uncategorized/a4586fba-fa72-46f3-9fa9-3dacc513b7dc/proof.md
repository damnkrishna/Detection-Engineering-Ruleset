# Proof — a4586fba-fa72-46f3-9fa9-3dacc513b7dc

## Rule

- **Rule ID:** a4586fba-fa72-46f3-9fa9-3dacc513b7dc
- **Rule name:** LSASS Suspicious Image Load (AN0757-B)
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
| `event_id` | event_id eq 7 | `7` |
| `image_path` | image_path regex .*\Q\lsass.exe\E$ | `C:\Windows\System32\lsass.exe` |
| `image_loaded` | image_loaded eq * AND image_loaded not_starts_with C:\Windows\System32\ AND image_loaded not_starts_with C:\Windows\SysWOW64\ AND image_loaded not_starts_with C:\Program Files\ AND image_loaded not_starts_with C:\Program Files (x86)\ | `*` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=7<br>`image_path`=C:\Windows\System32\lsass.exe<br>`image_loaded`=*<br>`hostname`=ENG-WKS-277<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.168.73`
- alert `401a207fd25856f3ba191f0022f36eba` on lane `entity_key` = `10.42.168.73`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=7<br>`image_path`=C:\Windows\System32\cmd.exe\lsass.exe<br>`image_loaded`=*<br>`hostname`=HR-WKS-276<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.167.73`
- alert `5e6d644565a3bdb2edb35a0c412dcb6d` on lane `entity_key` = `10.42.167.73`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_loaded not_starts_with C:\Program Files (x86)\' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=7<br>`image_path`=C:\Windows\System32\lsass.exe<br>`image_loaded`=C:\Program Files (x86)\C:\Windows\System32\amsi.dll<br>`hostname`=ENG-WKS-277<br>… | image_loaded=C:\Program Files (x86)\C:\Windows\System32\amsi.dll fails 'image_loaded not_starts_with C:\Program Files (x86)\' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.168.73`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\lsass.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=7<br>`image_path`=C:\Windows\System32\lsass.exe.bak<br>`image_loaded`=*<br>`hostname`=ENG-WKS-277<br>… | image_path=C:\Windows\System32\lsass.exe.bak fails 'image_path regex .*\Q\lsass.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.168.73`

