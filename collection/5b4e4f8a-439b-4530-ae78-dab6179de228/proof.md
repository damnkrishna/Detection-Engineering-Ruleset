# Proof — 5b4e4f8a-439b-4530-ae78-dab6179de228

## Rule

- **Rule ID:** 5b4e4f8a-439b-4530-ae78-dab6179de228
- **Rule name:** Collection - Anomaly Video Capture Library Load (AN0568)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [collection] / [T1125]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_loaded` | image_loaded regex .*\Q\avicap32.dll\E$ | `C:\Windows\System32\avicap32.dll` |
| `image_path` | image_path not_regex .*\Q\chrome.exe\E$ AND image_path not_regex .*\Q\msedge.exe\E$ AND image_path not_regex .*\Q\teams.exe\E$ AND image_path not_regex .*\Q\zoom.exe\E$ AND image_path not_regex .*\Q\skype.exe\E$ AND image_path not_regex .*\Q\WindowsCamera.exe\E$ AND image_path not_regex .*\Q\obs64.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_loaded`=C:\Windows\System32\avicap32.dll<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-450<br>`agent_ip`=10.42.141.107<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.141.107`
- alert `7ae1364cf5731ed968e2f2f35737dcb1` on lane `entity_key` = `10.42.141.107`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `image_loaded`=C:\Windows\System32\amsi.dll\avicap32.dll<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=SEC-WKS-449<br>`agent_ip`=10.42.140.107<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.140.107`
- alert `52f1301312a22eb6214431c42f0e986a` on lane `entity_key` = `10.42.140.107`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\obs64.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_loaded`=C:\Windows\System32\avicap32.dll<br>`image_path`=\obs64.exe<br>`hostname`=FIN-WKS-450<br>`agent_ip`=10.42.141.107<br>… | image_path=\obs64.exe fails 'image_path not_regex .*\Q\obs64.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.141.107`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_loaded regex .*\Q\avicap32.dll\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_loaded`=C:\Windows\System32\avicap32.dll.bak<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-450<br>`agent_ip`=10.42.141.107<br>… | image_loaded=C:\Windows\System32\avicap32.dll.bak fails 'image_loaded regex .*\Q\avicap32.dll\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.141.107`

