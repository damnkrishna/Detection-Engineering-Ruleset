# Proof — d83fdf14-ec32-4d2b-9ca9-adfc0157cf86

## Rule

- **Rule ID:** d83fdf14-ec32-4d2b-9ca9-adfc0157cf86
- **Rule name:** Registry Persistence Key Deletion (AN0113-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [defense-evasion] / [T1070.009]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `registry_event_type` | registry_event_type eq DeleteValue | `DeleteValue` |
| `target_object` | target_object contains \SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\` |
| `image_path` | image_path not_regex .*\Q\msiexec.exe\E$ AND image_path not_regex .*\Q\setup.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `registry_event_type`=DeleteValue<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SOFTWA…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=ENG-WKS-852<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.43.201`
- alert `7da1fa7cea3be4c8b14d4b64b27ef9d5` on lane `entity_key` = `10.42.43.201`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `registry_event_type`=DeleteValue<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDri…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=HR-WKS-851<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.42.201`
- alert `95d16b52b01e232d52d77b8475ffc80f` on lane `entity_key` = `10.42.42.201`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\setup.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `registry_event_type`=DeleteValue<br>`target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SOFTWA…<br>`image_path`=\setup.exe<br>`hostname`=ENG-WKS-852<br>… | image_path=\setup.exe fails 'image_path not_regex .*\Q\setup.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.43.201`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_object contains \SOFTWARE\Microsoft\Windows\CurrentVersion\Run\' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `registry_event_type`=DeleteValue<br>`target_object`=HKLM\SOFTWARE\Contoso\Reporting\LastRun<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=ENG-WKS-852<br>… | target_object=HKLM\SOFTWARE\Contoso\Reporting\LastRun fails 'target_object contains \SOFTWARE\Microsoft\Windows\CurrentVersion\Run\' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.43.201`

