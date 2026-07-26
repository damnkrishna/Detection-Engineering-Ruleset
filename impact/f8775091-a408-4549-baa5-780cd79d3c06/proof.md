# Proof — f8775091-a408-4549-baa5-780cd79d3c06

## Rule

- **Rule ID:** f8775091-a408-4549-baa5-780cd79d3c06
- **Rule name:** Volume Shadow Copy Deletion via Native Utilities (AN0602-C)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [impact] / [T1486]
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
| `original_filename` | original_filename in_list [vssadmin.exe, wmic.exe, wbadmin.exe, bcdedit.exe] | `vssadmin.exe` |
| `image_path` | image_path regex .*\Q\vssadmin.exe\E$ | `C:\Windows\System32\vssadmin.exe` |
| `cmd_line` | cmd_line contains delete shadows | `"C:\Windows\System32\cmd.exe" delete shadows` |
| `parent_image` | parent_image not_regex .*\Q\msiexec.exe\E$ AND parent_image not_regex .*\Q\backup.exe\E$ AND parent_image not_regex .*\Q\veeam.exe\E$ | `C:\Windows\explorer.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`original_filename`=vssadmin.exe<br>`image_path`=C:\Windows\System32\vssadmin.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" delete shadows C:\Users\Pub…<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; operates on a staging-directory path, which is what marks the process suspicious and backs the rule's high-rarity ATT&CK claim [T1486] |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.31.112`
- alert `4ccdd68708f58572655621dc561bc6ca` on lane `entity_key` = `10.42.31.112`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`original_filename`=wmic.exe<br>`image_path`=C:\Windows\System32\cmd.exe\wmic.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami shadowcopy delete…<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; operates on a staging-directory path, which is what marks the process suspicious and backs the rule's high-rarity ATT&CK claim [T1486] |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.30.112`
- alert `6d9a58b1d880b365d9d14ead3afe2d74` on lane `entity_key` = `10.42.30.112`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'parent_image not_regex .*\Q\veeam.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`original_filename`=vssadmin.exe<br>`image_path`=C:\Windows\System32\vssadmin.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" delete shadows C:\Users\Pub…<br>… | parent_image=\veeam.exe fails 'parent_image not_regex .*\Q\veeam.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.31.112`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains delete shadows' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`original_filename`=vssadmin.exe<br>`image_path`=C:\Windows\System32\vssadmin.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami fails 'cmd_line contains delete shadows' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.31.112`

