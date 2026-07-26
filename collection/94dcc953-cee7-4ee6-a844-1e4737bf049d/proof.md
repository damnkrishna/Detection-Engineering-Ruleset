# Proof — 94dcc953-cee7-4ee6-a844-1e4737bf049d

## Rule

- **Rule ID:** 94dcc953-cee7-4ee6-a844-1e4737bf049d
- **Rule name:** Collection - Browser Process Access and Session Hijacking (AN1398)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [collection] / [T1185]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `target_image` | target_image regex .*\Q\chrome.exe\E$ | `C:\Windows\System32\chrome.exe` |
| `source_image` | source_image regex .*\Q\powershell.exe\E$ | `C:\Windows\System32\powershell.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `target_image`=C:\Windows\System32\chrome.exe<br>`source_image`=C:\Windows\System32\powershell.exe<br>`hostname`=HR-WKS-246<br>`agent_ip`=10.42.137.109<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.137.109`
- alert `b473c9e14c897ec21f34e86e1ce5377c` on lane `entity_key` = `10.42.137.109`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `target_image`=C:\Windows\System32\lsass.exe\msedge.exe<br>`source_image`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-245<br>`agent_ip`=10.42.136.109<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.136.109`
- alert `d27b59456a73ffefca78aff7b2c43b80` on lane `entity_key` = `10.42.136.109`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'source_image regex .*\Q\powershell.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `target_image`=C:\Windows\System32\chrome.exe<br>`source_image`=C:\Windows\System32\powershell.exe.bak<br>`hostname`=HR-WKS-246<br>`agent_ip`=10.42.137.109<br>… | source_image=C:\Windows\System32\powershell.exe.bak fails 'source_image regex .*\Q\powershell.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.137.109`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_image regex .*\Q\chrome.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `target_image`=C:\Windows\System32\chrome.exe.bak<br>`source_image`=C:\Windows\System32\powershell.exe<br>`hostname`=HR-WKS-246<br>`agent_ip`=10.42.137.109<br>… | target_image=C:\Windows\System32\chrome.exe.bak fails 'target_image regex .*\Q\chrome.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.137.109`

