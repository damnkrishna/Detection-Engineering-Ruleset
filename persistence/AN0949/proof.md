# Proof — AN0949

## Rule

- **Rule ID:** AN0949
- **Rule name:** AN0949 - Compromise Host Software Binary
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [persistence] / [T1554]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `registry_event_type` | registry_event_type eq CreateFile | `CreateFile` |
| `file_path` | file_path regex .*\Q\wbem\WmiPrvSE.exe\E$ | `C:\Users\j.mercer\AppData\Local\Temp\wbem\WmiPrvSE.exe` |
| `image_path` | image_path not_starts_with C:\Windows\System32\ | `C:\Windows\System32` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `registry_event_type`=CreateFile<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\wbem\WmiPrvSE.exe<br>`image_path`=C:\Windows\System32<br>`hostname`=OPS-WKS-858<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.49.159`
- alert `099a25af5307c9e7fee456b8503c3cf2` on lane `entity_key` = `10.42.49.159`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `registry_event_type`=CreateFile<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp\System32\…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=ENG-WKS-857<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.48.159`
- alert `abb0b1ef80903ec019ff511ec83d508c` on lane `entity_key` = `10.42.48.159`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'file_path regex .*\Q\wbem\WmiPrvSE.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `registry_event_type`=CreateFile<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\wbem\WmiPrvSE.exe.bak<br>`image_path`=C:\Windows\System32<br>`hostname`=OPS-WKS-858<br>… | file_path=C:\Users\j.mercer\AppData\Local\Temp\wbem\WmiPrvSE.exe.bak fails 'file_path regex .*\Q\wbem\WmiPrvSE.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.49.159`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'registry_event_type eq CreateFile' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `registry_event_type`=CreateFile.bak<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\wbem\WmiPrvSE.exe<br>`image_path`=C:\Windows\System32<br>`hostname`=OPS-WKS-858<br>… | registry_event_type=CreateFile.bak fails 'registry_event_type eq CreateFile' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.49.159`

