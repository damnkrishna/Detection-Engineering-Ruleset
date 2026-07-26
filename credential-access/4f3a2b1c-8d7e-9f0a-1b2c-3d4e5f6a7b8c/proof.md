# Proof — 4f3a2b1c-8d7e-9f0a-1b2c-3d4e5f6a7b8c

## Rule

- **Rule ID:** 4f3a2b1c-8d7e-9f0a-1b2c-3d4e5f6a7b8c
- **Rule name:** Suspicious AD FS Database Query for SAML Certificate Extraction via CLI (AN0420-A)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [credential-access, defense-evasion] / [T1606.002]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_path` | image_path regex .*\Q\sqlcmd.exe\E$ | `C:\Windows\System32\sqlcmd.exe` |
| `cmd_line` | cmd_line contains np:\\.\pipe\microsoft##ssee\tsql\query AND cmd_line contains AdfsConfiguration | `"C:\Windows\System32\cmd.exe" np:\\.\pipe\microsoft##ssee\tsql\query AdfsConfiguration` |
| `parent_image` | parent_image not_regex .*\Q\msiexec.exe\E$ AND parent_image not_regex .*\Q\setup.exe\E$ | `C:\Windows\explorer.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\sqlcmd.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" np:\\.\pipe\microsoft##ssee…<br>`parent_image`=C:\Windows\explorer.exe<br>`hostname`=OPS-WKS-433<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.124.182`
- alert `4daec36ae1d48757760ea1fd6eec528e` on lane `entity_key` = `10.42.124.182`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `original_filename`=pwsh.dll<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami Export-AdfsCertif…<br>`parent_image`=C:\Windows\explorer.exe<br>`hostname`=ENG-WKS-432<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.123.182`
- alert `bf19bafe80d856c72f556f5b5fdffd0c` on lane `entity_key` = `10.42.123.182`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'parent_image not_regex .*\Q\setup.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\sqlcmd.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" np:\\.\pipe\microsoft##ssee…<br>`parent_image`=\setup.exe<br>`hostname`=OPS-WKS-433<br>… | parent_image=\setup.exe fails 'parent_image not_regex .*\Q\setup.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.124.182`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains AdfsConfiguration' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\sqlcmd.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" np:\\.\pipe\microsoft##ssee…<br>`parent_image`=C:\Windows\explorer.exe<br>`hostname`=OPS-WKS-433<br>… | cmd_line="C:\Windows\System32\cmd.exe" np:\\.\pipe\microsoft##ssee\tsql\contoso-query AdfsConfiguration fails 'cmd_line contains AdfsConfiguration' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.124.182`

