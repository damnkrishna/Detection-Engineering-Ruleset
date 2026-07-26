# Proof — bc15854c-e232-478a-92ac-1f4d96247771

## Rule

- **Rule ID:** bc15854c-e232-478a-92ac-1f4d96247771
- **Rule name:** Collection - Anomaly Compression Library Load (AN0747)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [collection] / [T1560.002]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_loaded` | image_loaded regex .*\Q\zlib1.dll\E$ | `C:\Windows\System32\zlib1.dll` |
| `image_path` | image_path not_regex .*\Q\System32\msiexec.exe\E$ AND image_path not_regex .*\Q\Program Files\7-Zip\7zG.exe\E$ AND image_path not_regex .*\Q\Program Files\7-Zip\7z.exe\E$ AND image_path not_regex .*\Q\Program Files\WinRAR\WinRAR.exe\E$ AND image_path not_regex .*\Q\Program Files\Microsoft Office\root\Office16\* \E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_loaded`=C:\Windows\System32\zlib1.dll<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-225<br>`agent_ip`=10.42.16.100<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.16.100`
- alert `479e17416d289565a7a49b64e79886f5` on lane `entity_key` = `10.42.16.100`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `image_loaded`=C:\Windows\System32\amsi.dll\zlib.dll<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=SEC-WKS-224<br>`agent_ip`=10.42.15.100<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.15.100`
- alert `7e7080a5846a403be1c41cb552d6b16b` on lane `entity_key` = `10.42.15.100`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_loaded regex .*\Q\zlib1.dll\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_loaded`=C:\Windows\System32\zlib1.dll.bak<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-225<br>`agent_ip`=10.42.16.100<br>… | image_loaded=C:\Windows\System32\zlib1.dll.bak fails 'image_loaded regex .*\Q\zlib1.dll\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.16.100`

## benign_2

**Expected alerts:** 0  
**Construction:** the field 'image_path' is absent entirely; an absent field is no-match for every operator, so the stage is never entered

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_loaded`=C:\Windows\System32\zlib1.dll<br>`hostname`=FIN-WKS-225<br>`agent_ip`=10.42.16.100<br>`event_id`=7<br>… | carries no 'image_path' at all; evaluateCondition returns no-match for every operator on an absent field, so the stage gate rejects the event |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.16.100`

