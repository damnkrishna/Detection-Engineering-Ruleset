# Proof — 67879061-32be-4edb-83c3-66c3d77a1a5c

## Rule

- **Rule ID:** 67879061-32be-4edb-83c3-66c3d77a1a5c
- **Rule name:** Collection - Anomaly Audio Capture Library Load (AN0619)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [collection] / [T1123]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_loaded` | image_loaded regex .*\Q\winmm.dll\E$ | `C:\Windows\System32\winmm.dll` |
| `image_path` | image_path not_regex .*\Q\chrome.exe\E$ AND image_path not_regex .*\Q\msedge.exe\E$ AND image_path not_regex .*\Q\teams.exe\E$ AND image_path not_regex .*\Q\zoom.exe\E$ AND image_path not_regex .*\Q\skype.exe\E$ AND image_path not_regex .*\Q\slack.exe\E$ AND image_path not_regex .*\Q\discord.exe\E$ AND image_path not_regex .*\Q\audacity.exe\E$ AND image_path not_regex .*\Q\obs64.exe\E$ AND image_path not_regex .*\Q\SoundRecorder.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_loaded`=C:\Windows\System32\winmm.dll<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=OPS-WKS-598<br>`agent_ip`=10.42.189.173<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.189.173`
- alert `1cfd1450c45f8127f93026f750d7321c` on lane `entity_key` = `10.42.189.173`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `image_loaded`=C:\Windows\System32\amsi.dll\dsound.dll<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=ENG-WKS-597<br>`agent_ip`=10.42.188.173<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.188.173`
- alert `e9477ce898f1dbebdc0f0d634d929d90` on lane `entity_key` = `10.42.188.173`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\SoundRecorder.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_loaded`=C:\Windows\System32\winmm.dll<br>`image_path`=\SoundRecorder.exe<br>`hostname`=OPS-WKS-598<br>`agent_ip`=10.42.189.173<br>… | image_path=\SoundRecorder.exe fails 'image_path not_regex .*\Q\SoundRecorder.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.189.173`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_loaded regex .*\Q\winmm.dll\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_loaded`=C:\Windows\System32\winmm.dll.bak<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=OPS-WKS-598<br>`agent_ip`=10.42.189.173<br>… | image_loaded=C:\Windows\System32\winmm.dll.bak fails 'image_loaded regex .*\Q\winmm.dll\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.189.173`

