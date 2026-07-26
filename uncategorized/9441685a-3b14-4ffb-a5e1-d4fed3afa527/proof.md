# Proof — 9441685a-3b14-4ffb-a5e1-d4fed3afa527

## Rule

- **Rule ID:** 9441685a-3b14-4ffb-a5e1-d4fed3afa527
- **Rule name:** Hybrid Identity Agent DLL Modification (AN0814-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [] / [T1556.007]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id eq 11 | `11` |
| `file_path` | file_path contains C:\Program Files\Microsoft Azure AD Connection Tool\ AND file_path regex .*\Q.dll\E$ | `C:\Users\j.mercer\AppData\Local\Temp C:\Program Files\Microsoft Azure AD Connection Tool\.dll` |
| `image_path` | image_path not_regex .*\Q\trustedinstaller.exe\E$ AND image_path not_regex .*\Q\msiexec.exe\E$ AND image_path not_regex .*\Q\tiworker.exe\E$ AND image_path not_regex .*\Q\AzureADConnect.exe\E$ AND image_path not_regex .*\Q\AzureADConnectUpdater.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp C:\Program Files\Mic…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=SEC-WKS-869<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.60.184`
- alert `3392c019e13c239495fe2241997ccd1c` on lane `entity_key` = `10.42.60.184`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp\report.tmp C:\Progra…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-870<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.61.184`
- alert `b81f686b95a01ed68f92799ac79f11bc` on lane `entity_key` = `10.42.61.184`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\AzureADConnectUpdater.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp C:\Program Files\Mic…<br>`image_path`=\AzureADConnectUpdater.exe<br>`hostname`=SEC-WKS-869<br>… | image_path=\AzureADConnectUpdater.exe fails 'image_path not_regex .*\Q\AzureADConnectUpdater.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.60.184`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'file_path regex .*\Q.dll\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=11<br>`file_path`=C:\Users\j.mercer\AppData\Local\Temp C:\Program Files\Mic…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=SEC-WKS-869<br>… | file_path=C:\Users\j.mercer\AppData\Local\Temp C:\Program Files\Microsoft Azure AD Connection Tool\.dll.bak fails 'file_path regex .*\Q.dll\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.60.184`

