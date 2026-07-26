# Proof — f023d881-819a-44f2-9ca0-80ef522f0018

## Rule

- **Rule ID:** f023d881-819a-44f2-9ca0-80ef522f0018
- **Rule name:** Suspicious Child Process of Service Control Manager (AN1185-A)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [execution] / [T1569.002]
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
| `parent_image` | parent_image regex .*\Q\services.exe\E$ | `C:\Windows\services.exe` |
| `image_path` | image_path not_regex .*\Q\system32\svchost.exe\E$ AND image_path not_regex .*\Q\system32\spoolsv.exe\E$ AND image_path not_regex .*\Q\system32\lsass.exe\E$ AND image_path not_regex .*\Q\system32\wininit.exe\E$ AND image_path not_regex .*\Q\system32\searchindexer.exe\E$ AND image_path not_regex .*\Q\system32\taskhostw.exe\E$ AND image_path not_regex .*\Q\system32\dllhost.exe\E$ AND image_path not_regex .*\Q\system32\sihost.exe\E$ AND image_path not_regex .*\Q\system32\mstsc.exe\E$ AND image_path not_regex .*\Q\system32\consent.exe\E$ AND image_path not_regex .*\Q\system32\smartscreen.exe\E$ AND image_path not_regex .*\Q\system32\runtimebroker.exe\E$ AND image_path not_regex .*\Q\system32\wbem\WmiPrvSE.exe\E$ AND image_path not_regex .*\Q\MsMpEng.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`parent_image`=C:\Windows\services.exe<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-630<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.121.152`
- alert `9c4ab106dfada7122d5ff14e09a4e92e` on lane `entity_key` = `10.42.121.152`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`parent_image`=C:\Windows\explorer.exe\services.exe<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=HR-WKS-631<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.122.152`
- alert `631792b54283865c42f3466e981e2242` on lane `entity_key` = `10.42.122.152`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\MsMpEng.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`parent_image`=C:\Windows\services.exe<br>`image_path`=\MsMpEng.exe<br>`hostname`=FIN-WKS-630<br>… | image_path=\MsMpEng.exe fails 'image_path not_regex .*\Q\MsMpEng.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.121.152`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'parent_image regex .*\Q\services.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`parent_image`=C:\Windows\services.exe.bak<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-630<br>… | parent_image=C:\Windows\services.exe.bak fails 'parent_image regex .*\Q\services.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.121.152`

