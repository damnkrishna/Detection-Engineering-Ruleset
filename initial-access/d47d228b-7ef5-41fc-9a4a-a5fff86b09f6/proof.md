# Proof — d47d228b-7ef5-41fc-9a4a-a5fff86b09f6

## Rule

- **Rule ID:** d47d228b-7ef5-41fc-9a4a-a5fff86b09f6
- **Rule name:** Spearphishing Attachment - Dangerous File Written by Mail Client (AN0655-A)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [initial-access] / [T1566.001]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_path` | image_path regex .*\Q\outlook.exe\E$ | `C:\Windows\System32\outlook.exe` |
| `file_path` | file_path regex .*\Q.exe\E$ | `C:\Users\j.mercer\AppData\Local\Temp\.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\outlook.exe<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\.exe<br>`hostname`=ENG-WKS-137<br>`agent_ip`=10.42.128.207<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.128.207`
- alert `1235b2f3fe6bc41dcd29da897113cf24` on lane `entity_key` = `10.42.128.207`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `image_path`=C:\Windows\System32\cmd.exe\thunderbird.exe<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp\.lnk<br>`hostname`=OPS-WKS-138<br>`agent_ip`=10.42.129.207<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.129.207`
- alert `f3f8d7c6c7e0ccbc1f918985212056fb` on lane `entity_key` = `10.42.129.207`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'file_path regex .*\Q.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\outlook.exe<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\.exe.bak<br>`hostname`=ENG-WKS-137<br>`agent_ip`=10.42.128.207<br>… | file_path=C:\Users\j.mercer\AppData\Local\Temp\.exe.bak fails 'file_path regex .*\Q.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.128.207`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\outlook.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\outlook.exe.bak<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\.exe<br>`hostname`=ENG-WKS-137<br>`agent_ip`=10.42.128.207<br>… | image_path=C:\Windows\System32\outlook.exe.bak fails 'image_path regex .*\Q\outlook.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.128.207`

