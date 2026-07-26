# Proof — c57f8e8a-2c1b-4d92-8c7a-5f6d7e8a9b0d

## Rule

- **Rule ID:** c57f8e8a-2c1b-4d92-8c7a-5f6d7e8a9b0d
- **Rule name:** Elevated Execution from Weak Permissions Installer Directory (AN0108)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [execution, persistence, privilege-escalation] / [T1574.005]
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
| `integrity_level` | integrity_level in_list [High, System] | `High` |
| `image_path` | image_path contains \AppData\Local\Temp\ AND image_path not_regex .*\Q\msiexec.exe\E$ AND image_path not_regex .*\Q\setup.exe\E$ AND image_path not_regex .*\Q\install.exe\E$ | `C:\Windows\System32\AppData\Local\Temp\` |
| `cmd_line` | cmd_line not_contains nativeimages AND cmd_line not_contains PackageStaging | `"C:\Windows\System32\cmd.exe" /c whoami` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`integrity_level`=High<br>`image_path`=C:\Windows\System32\AppData\Local\Temp\<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.34.107`
- alert `fd33c42c4e798566be83c74242315633` on lane `entity_key` = `10.42.34.107`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`integrity_level`=System<br>`image_path`=C:\Windows\System32\cmd.exe\Users\Public\<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.35.107`
- alert `b5140049ef9c8feb2ccce38b495bf11e` on lane `entity_key` = `10.42.35.107`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\install.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`integrity_level`=High<br>`image_path`=\install.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>… | image_path=\install.exe fails 'image_path not_regex .*\Q\install.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.34.107`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line not_contains PackageStaging' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`integrity_level`=High<br>`image_path`=C:\Windows\System32\AppData\Local\Temp\<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami PackageStaging<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami PackageStaging fails 'cmd_line not_contains PackageStaging' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.34.107`

