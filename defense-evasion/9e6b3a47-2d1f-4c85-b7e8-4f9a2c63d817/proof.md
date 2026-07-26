# Proof — 9e6b3a47-2d1f-4c85-b7e8-4f9a2c63d817

## Rule

- **Rule ID:** 9e6b3a47-2d1f-4c85-b7e8-4f9a2c63d817
- **Rule name:** Microsoft-Signed Script Proxy Execution (AN2101)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [defense-evasion] / [T1216]
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
| `image_path` | image_path regex .*\Q\cscript.exe\E$ | `C:\Windows\System32\cscript.exe` |
| `cmd_line` | cmd_line contains pubprn.vbs AND cmd_line not_contains slmgr.vbs /ato AND cmd_line not_contains slmgr.vbs /dlv AND cmd_line not_contains slmgr.vbs /xpr AND cmd_line not_contains slmgr.vbs /dli AND cmd_line not_contains winrm.vbs quickconfig | `"C:\Windows\System32\cmd.exe" pubprn.vbs` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\cscript.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" pubprn.vbs<br>`hostname`=SEC-WKS-559<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.150.90`
- alert `bb9291dc9334ad57182b5ecb87077403` on lane `entity_key` = `10.42.150.90`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`original_filename`=wscript.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami manage-bde.wsf<br>`hostname`=FIN-WKS-560<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.151.90`
- alert `291f079135455e4d865d06df98a985fa` on lane `entity_key` = `10.42.151.90`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line not_contains winrm.vbs quickconfig' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\cscript.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami winrm.vbs quickco…<br>`hostname`=SEC-WKS-559<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami winrm.vbs quickconfig fails 'cmd_line not_contains winrm.vbs quickconfig' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.150.90`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\cscript.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`image_path`=C:\Windows\System32\cscript.exe.bak<br>`cmd_line`="C:\Windows\System32\cmd.exe" pubprn.vbs<br>`hostname`=SEC-WKS-559<br>… | image_path=C:\Windows\System32\cscript.exe.bak fails 'image_path regex .*\Q\cscript.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.150.90`

