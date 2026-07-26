# Proof — 360fdc81-c1b7-440a-8f86-db3e7218c92a

## Rule

- **Rule ID:** 360fdc81-c1b7-440a-8f86-db3e7218c92a
- **Rule name:** DHCP Spoofing Tool Execution (AN1290-A)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [collection] / [T1557.003]
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
| `original_filename` | original_filename in_list [yersinia.exe, dhcpstarv.exe] | `yersinia.exe` |
| `image_path` | image_path regex .*\Q\yersinia.exe\E$ | `C:\Windows\System32\yersinia.exe` |
| `parent_image` | parent_image not_regex .*\Q\msiexec.exe\E$ AND parent_image not_regex .*\Q\setup.exe\E$ | `C:\Windows\explorer.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`original_filename`=yersinia.exe<br>`image_path`=C:\Windows\System32\yersinia.exe<br>`parent_image`=C:\Windows\explorer.exe<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.104.128`
- alert `dd02b383df37853041f4cd0de8789f5c` on lane `entity_key` = `10.42.104.128`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami dhcpstarv<br>`parent_image`=C:\Windows\explorer.exe<br>`hostname`=SEC-WKS-514<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.105.128`
- alert `81acd1476bc30b55ffb50f7f6f107959` on lane `entity_key` = `10.42.105.128`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'parent_image not_regex .*\Q\setup.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`original_filename`=yersinia.exe<br>`image_path`=C:\Windows\System32\yersinia.exe<br>`parent_image`=\setup.exe<br>… | parent_image=\setup.exe fails 'parent_image not_regex .*\Q\setup.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.104.128`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\yersinia.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`original_filename`=yersinia.exe<br>`image_path`=C:\Windows\System32\yersinia.exe.bak<br>`parent_image`=C:\Windows\explorer.exe<br>… | image_path=C:\Windows\System32\yersinia.exe.bak fails 'image_path regex .*\Q\yersinia.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.104.128`

