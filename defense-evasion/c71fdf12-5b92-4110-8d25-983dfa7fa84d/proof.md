# Proof — c71fdf12-5b92-4110-8d25-983dfa7fa84d

## Rule

- **Rule ID:** c71fdf12-5b92-4110-8d25-983dfa7fa84d
- **Rule name:** Suspicious Electron Library Load (AN0071-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
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
| `image_loaded` | image_loaded regex .*\Q\node.dll\E$ | `C:\Windows\System32\node.dll` |
| `image_path` | image_path not_regex .*\Q\chrome.exe\E$ AND image_path not_regex .*\Q\msedge.exe\E$ AND image_path not_regex .*\Q\slack.exe\E$ AND image_path not_regex .*\Q\Teams.exe\E$ AND image_path not_regex .*\Q\Code.exe\E$ AND image_path not_regex .*\Q\discord.exe\E$ AND image_path not_regex .*\Q\explorer.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_loaded`=C:\Windows\System32\node.dll<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=OPS-WKS-243<br>`agent_ip`=10.42.34.66<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.34.66`
- alert `a877642472c795fdc053a6c7f741645d` on lane `entity_key` = `10.42.34.66`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `image_loaded`=C:\Windows\System32\amsi.dll\electron.dll<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=SEC-WKS-244<br>`agent_ip`=10.42.35.66<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.35.66`
- alert `fadbeff9fe5b7ce8b21d33dcf5da6f02` on lane `entity_key` = `10.42.35.66`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\explorer.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_loaded`=C:\Windows\System32\node.dll<br>`image_path`=\explorer.exe<br>`hostname`=OPS-WKS-243<br>`agent_ip`=10.42.34.66<br>… | image_path=\explorer.exe fails 'image_path not_regex .*\Q\explorer.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.34.66`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_loaded regex .*\Q\node.dll\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_loaded`=C:\Windows\System32\node.dll.bak<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=OPS-WKS-243<br>`agent_ip`=10.42.34.66<br>… | image_loaded=C:\Windows\System32\node.dll.bak fails 'image_loaded regex .*\Q\node.dll\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.34.66`

