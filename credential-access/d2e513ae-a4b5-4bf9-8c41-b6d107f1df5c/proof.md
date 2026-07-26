# Proof — d2e513ae-a4b5-4bf9-8c41-b6d107f1df5c

## Rule

- **Rule ID:** d2e513ae-a4b5-4bf9-8c41-b6d107f1df5c
- **Rule name:** Suspicious SAM Registry Hive Export via File Event (AN0235-C)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [credential-access] / [T1003.002]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `file_path` | file_path contains \AppData\Local\Temp\ AND file_path regex .*\Q\sam\E$ | `C:\Users\j.mercer\AppData\Local\Temp\AppData\Local\Temp\\sam` |
| `image_path` | image_path not_starts_with C:\Windows\System32\ AND image_path not_starts_with C:\Windows\SysWOW64\ | `C:\Windows\System32` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\AppData\Local\Temp\\sam<br>`image_path`=C:\Windows\System32<br>`hostname`=HR-WKS-641<br>`agent_ip`=10.42.32.31<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; operates on a staging-directory path, which is what marks the process suspicious and backs the rule's high-rarity ATT&CK claim [T1003.002] |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.32.31`
- alert `ffd16076682b68125eac922907c5e3be` on lane `entity_key` = `10.42.32.31`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp C:\Window…<br>`image_path`=C:\Windows\System32<br>`hostname`=ENG-WKS-642<br>`agent_ip`=10.42.33.31<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; operates on a staging-directory path, which is what marks the process suspicious and backs the rule's high-rarity ATT&CK claim [T1003.002] |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.33.31`
- alert `e184c0e3c1370202372bdb8bbcdf4227` on lane `entity_key` = `10.42.33.31`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_starts_with C:\Windows\SysWOW64\' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\AppData\Local\Temp\\sam<br>`image_path`=C:\Windows\SysWOW64\C:\Windows\System32\cmd.exe<br>`hostname`=HR-WKS-641<br>`agent_ip`=10.42.32.31<br>… | image_path=C:\Windows\SysWOW64\C:\Windows\System32\cmd.exe fails 'image_path not_starts_with C:\Windows\SysWOW64\' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.32.31`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'file_path regex .*\Q\sam\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\AppData\Local\Temp\\…<br>`image_path`=C:\Windows\System32<br>`hostname`=HR-WKS-641<br>`agent_ip`=10.42.32.31<br>… | file_path=C:\Users\j.mercer\AppData\Local\Temp\AppData\Local\Temp\\contoso-sam fails 'file_path regex .*\Q\sam\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.32.31`

