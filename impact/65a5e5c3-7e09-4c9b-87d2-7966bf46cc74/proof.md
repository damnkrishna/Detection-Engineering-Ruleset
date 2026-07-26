# Proof — 65a5e5c3-7e09-4c9b-87d2-7966bf46cc74

## Rule

- **Rule ID:** 65a5e5c3-7e09-4c9b-87d2-7966bf46cc74
- **Rule name:** Exploit Framework Induced Denial of Service Execution (AN0850-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [impact] / [T1499.004]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id eq 1 | `1` |
| `cmd_line` | cmd_line contains exploit/windows/dos/ | `"C:\Windows\System32\cmd.exe" exploit/windows/dos/` |
| `parent_image` | parent_image not_regex .*\Q\burp.exe\E$ AND parent_image not_regex .*\Q\metasploit.exe\E$ | `C:\Windows\explorer.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`="C:\Windows\System32\cmd.exe" exploit/windows/dos/<br>`parent_image`=C:\Windows\explorer.exe<br>`hostname`=HR-WKS-771<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.162.69`
- alert `3b6d6fb440b0cdec799c53360a2e6f19` on lane `entity_key` = `10.42.162.69`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami exploit/linux/dos/<br>`parent_image`=C:\Windows\explorer.exe<br>`hostname`=ENG-WKS-772<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.163.69`
- alert `ca4aaf2b5fed12199ba521194d466a46` on lane `entity_key` = `10.42.163.69`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'parent_image not_regex .*\Q\metasploit.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`="C:\Windows\System32\cmd.exe" exploit/windows/dos/<br>`parent_image`=\metasploit.exe<br>`hostname`=HR-WKS-771<br>… | parent_image=\metasploit.exe fails 'parent_image not_regex .*\Q\metasploit.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.162.69`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains exploit/windows/dos/' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>`parent_image`=C:\Windows\explorer.exe<br>`hostname`=HR-WKS-771<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami fails 'cmd_line contains exploit/windows/dos/' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.162.69`

