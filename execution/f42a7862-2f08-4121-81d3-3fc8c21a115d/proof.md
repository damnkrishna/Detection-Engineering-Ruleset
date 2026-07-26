# Proof — f42a7862-2f08-4121-81d3-3fc8c21a115d

## Rule

- **Rule ID:** f42a7862-2f08-4121-81d3-3fc8c21a115d
- **Rule name:** Suspicious JavaScript Execution via WSH (AN0733)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [execution] / [T1059.007]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_path` | image_path regex .*\Q\wscript.exe\E$ | `C:\Windows\System32\wscript.exe` |
| `cmd_line` | cmd_line contains .js | `"C:\Windows\System32\cmd.exe" .js` |
| `parent_image` | parent_image regex .*\Q\winword.exe\E$ | `C:\Windows\winword.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\wscript.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" .js<br>`parent_image`=C:\Windows\winword.exe<br>`hostname`=OPS-WKS-623<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.14.79`
- alert `439dfc25ff5458104af8f6ad0494015e` on lane `entity_key` = `10.42.14.79`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `image_path`=C:\Windows\System32\cmd.exe\cscript.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami .jse\Downloads\<br>`hostname`=SEC-WKS-624<br>`agent_ip`=10.42.15.79<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.15.79`
- alert `bb05bbc429c839d610d9f9d3af5beed4` on lane `entity_key` = `10.42.15.79`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'parent_image regex .*\Q\winword.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\wscript.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" .js<br>`parent_image`=C:\Windows\winword.exe.bak<br>`hostname`=OPS-WKS-623<br>… | parent_image=C:\Windows\winword.exe.bak fails 'parent_image regex .*\Q\winword.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.14.79`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains .js' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\wscript.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>`parent_image`=C:\Windows\winword.exe<br>`hostname`=OPS-WKS-623<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami fails 'cmd_line contains .js' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.14.79`

