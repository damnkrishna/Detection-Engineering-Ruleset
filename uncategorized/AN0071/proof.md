# Proof — AN0071

## Rule

- **Rule ID:** AN0071
- **Rule name:** Electron Application Abuse for Proxy Execution (AN0071)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [defense-evasion] / [T1218.015]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_path` | image_path contains \Microsoft\Teams\current\Teams.exe | `C:\Windows\System32\Microsoft\Teams\current\Teams.exe` |
| `cmd_line` | cmd_line contains --gpu-launcher | `"C:\Windows\System32\cmd.exe" --gpu-launcher` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\Microsoft\Teams\current\Teams.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" --gpu-launcher<br>`hostname`=ENG-WKS-362<br>`agent_ip`=10.42.53.109<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.53.109`
- alert `ea9c51a392d3f90675d13369ce6b24a1` on lane `entity_key` = `10.42.53.109`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `parent_image`=C:\Windows\explorer.exe\Slack\slack.exe<br>`image_path`=C:\Windows\System32\cmd.exe\powershell.exe<br>`hostname`=HR-WKS-361<br>`agent_ip`=10.42.52.109<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.52.109`
- alert `72a788ac21a5d295dba107bebbb3169f` on lane `entity_key` = `10.42.52.109`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains --gpu-launcher' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\Microsoft\Teams\current\Teams.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>`hostname`=ENG-WKS-362<br>`agent_ip`=10.42.53.109<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami fails 'cmd_line contains --gpu-launcher' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.53.109`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path contains \Microsoft\Teams\current\Teams.exe' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\Microsoft\Teams\current\Teams_helper.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" --gpu-launcher<br>`hostname`=ENG-WKS-362<br>`agent_ip`=10.42.53.109<br>… | image_path=C:\Windows\System32\Microsoft\Teams\current\Teams_helper.exe fails 'image_path contains \Microsoft\Teams\current\Teams.exe' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.53.109`

