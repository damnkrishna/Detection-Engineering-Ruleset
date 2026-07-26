# Proof — 43f1108d-b079-4a5d-b151-6e2f9c631d6a

## Rule

- **Rule ID:** 43f1108d-b079-4a5d-b151-6e2f9c631d6a
- **Rule name:** Spearphishing Link - Browser Spawned by Mail/Chat App with Suspicious URL (AN0298-A)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [initial-access] / [T1566.002]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `parent_image` | parent_image regex .*\Q\outlook.exe\E$ | `C:\Windows\outlook.exe` |
| `image_path` | image_path regex .*\Q\chrome.exe\E$ | `C:\Windows\System32\chrome.exe` |
| `cmd_line` | cmd_line contains file:// | `"C:\Windows\System32\cmd.exe" file://` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `parent_image`=C:\Windows\outlook.exe<br>`image_path`=C:\Windows\System32\chrome.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" file://<br>`hostname`=HR-WKS-771<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.62.53`
- alert `c96e73900631335d7e5bfc08f70cd751` on lane `entity_key` = `10.42.62.53`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `parent_image`=C:\Windows\explorer.exe\thunderbird.exe<br>`image_path`=C:\Windows\System32\cmd.exe\msedge.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami\\\\<br>`hostname`=FIN-WKS-770<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.61.53`
- alert `f8541143c9e2054adf180d5c224d9b31` on lane `entity_key` = `10.42.61.53`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains file://' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `parent_image`=C:\Windows\outlook.exe<br>`image_path`=C:\Windows\System32\chrome.exe<br>`cmd_line`=contoso-reporting<br>`hostname`=HR-WKS-771<br>… | cmd_line=contoso-reporting fails 'cmd_line contains file://' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.62.53`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\chrome.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `parent_image`=C:\Windows\outlook.exe<br>`image_path`=C:\Windows\System32\chrome.exe.bak<br>`cmd_line`="C:\Windows\System32\cmd.exe" file://<br>`hostname`=HR-WKS-771<br>… | image_path=C:\Windows\System32\chrome.exe.bak fails 'image_path regex .*\Q\chrome.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.62.53`

