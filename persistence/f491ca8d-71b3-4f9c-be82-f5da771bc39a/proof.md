# Proof — f491ca8d-71b3-4f9c-be82-f5da771bc39a

## Rule

- **Rule ID:** f491ca8d-71b3-4f9c-be82-f5da771bc39a
- **Rule name:** Malicious Office Add-in Drop for Persistence (AN0137-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [persistence] / [T1137.006]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `file_path` | file_path contains \Microsoft\Word\Startup\ | `C:\Users\j.mercer\AppData\Local\Temp\Microsoft\Word\Startup\` |
| `image_path` | image_path not_contains \OfficeClickToRun.exe AND image_path not_contains \OfficeC2RClient.exe AND image_path not_contains \setup.exe | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\Microsoft\Word\Startup\<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=SEC-WKS-884<br>`agent_ip`=10.42.175.121<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.175.121`
- alert `5886a0d3e2894d093d84b7200ae2b0a3` on lane `entity_key` = `10.42.175.121`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp\.xll<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-885<br>`agent_ip`=10.42.176.121<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.176.121`
- alert `d1f89dcf85c100515a2d304f30d6a119` on lane `entity_key` = `10.42.176.121`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_contains \setup.exe' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\Microsoft\Word\Startup\<br>`image_path`=C:\Windows\System32\cmd.exe \setup.exe<br>`hostname`=SEC-WKS-884<br>`agent_ip`=10.42.175.121<br>… | image_path=C:\Windows\System32\cmd.exe \setup.exe fails 'image_path not_contains \setup.exe' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.175.121`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'file_path contains \Microsoft\Word\Startup\' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=SEC-WKS-884<br>`agent_ip`=10.42.175.121<br>… | file_path=C:\Users\j.mercer\AppData\Local\Temp\report.tmp fails 'file_path contains \Microsoft\Word\Startup\' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.175.121`

