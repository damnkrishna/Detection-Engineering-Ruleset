# Proof — 8d2dfdf1-ec32-4e2b-9ca9-adfc0157cf89

## Rule

- **Rule ID:** 8d2dfdf1-ec32-4e2b-9ca9-adfc0157cf89
- **Rule name:** Security Software Registry Key Modifications (AN0048-C)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [discovery] / [T1518.001]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `target_object` | target_object contains HKLM\SOFTWARE\Microsoft\Windows Defender | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run HKLM\SOFTWARE\Microsoft\Windows Defender` |
| `image_path` | image_path not_regex .*\Q\MsMpEng.exe\E$ AND image_path not_regex .*\Q\NisSrv.exe\E$ AND image_path not_regex .*\Q\SenseIR.exe\E$ AND image_path not_regex .*\Q\SenseCncProxy.exe\E$ AND image_path not_regex .*\Q\wininit.exe\E$ AND image_path not_regex .*\Q\services.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run HKLM\S…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=OPS-WKS-693<br>`agent_ip`=10.42.84.128<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.84.128`
- alert `46b891b70675876097ac66f2f36dfef3` on lane `entity_key` = `10.42.84.128`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDri…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=ENG-WKS-692<br>`agent_ip`=10.42.83.128<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.83.128`
- alert `89a4f3bcec34e1b87bea8f202ac14c06` on lane `entity_key` = `10.42.83.128`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\services.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run HKLM\S…<br>`image_path`=\services.exe<br>`hostname`=OPS-WKS-693<br>`agent_ip`=10.42.84.128<br>… | image_path=\services.exe fails 'image_path not_regex .*\Q\services.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.84.128`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_object contains HKLM\SOFTWARE\Microsoft\Windows Defender' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `target_object`=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run HKLM\S…<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=OPS-WKS-693<br>`agent_ip`=10.42.84.128<br>… | target_object=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run HKLM\SOFTWARE\Microsoft\contoso-Windows Defender fails 'target_object contains HKLM\SOFTWARE\Microsoft\Windows Defender' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.84.128`

