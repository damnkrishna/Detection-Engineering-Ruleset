# Proof — a39db5a7-d1df-40fd-bedd-01a27a176f4d

## Rule

- **Rule ID:** a39db5a7-d1df-40fd-bedd-01a27a176f4d
- **Rule name:** Software Supply Chain - Installer Writing Suspicious File (AN0862-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [initial-access] / [T1195.002]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_path` | image_path regex .*\Q\msiexec.exe\E$ | `C:\Windows\System32\msiexec.exe` |
| `file_path` | file_path contains \Start Menu\Programs\Startup\ AND file_path regex .*\Q.bat\E$ | `C:\Users\j.mercer\AppData\Local\Temp\Start Menu\Programs\Startup\.bat` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\msiexec.exe<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\Start Menu\Programs\…<br>`hostname`=SEC-WKS-879<br>`agent_ip`=10.42.70.197<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.70.197`
- alert `17b9e0a6b3dcf2a5edc9ff5cb55a6d84` on lane `entity_key` = `10.42.70.197`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `image_path`=C:\Windows\System32\cmd.exe\setup.exe<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp\Windows\S…<br>`hostname`=FIN-WKS-880<br>`agent_ip`=10.42.71.197<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.71.197`
- alert `35b8389506de3d5c67042b1613448f29` on lane `entity_key` = `10.42.71.197`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'file_path regex .*\Q.bat\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\msiexec.exe<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\Start Menu\Programs\…<br>`hostname`=SEC-WKS-879<br>`agent_ip`=10.42.70.197<br>… | file_path=C:\Users\j.mercer\AppData\Local\Temp\Start Menu\Programs\Startup\.bat.bak fails 'file_path regex .*\Q.bat\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.70.197`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\msiexec.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\msiexec.exe.bak<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\Start Menu\Programs\…<br>`hostname`=SEC-WKS-879<br>`agent_ip`=10.42.70.197<br>… | image_path=C:\Windows\System32\msiexec.exe.bak fails 'image_path regex .*\Q\msiexec.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.70.197`

