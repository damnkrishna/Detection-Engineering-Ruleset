# Proof — f315c173-354b-4ba5-a014-6e2f2d3f2764

## Rule

- **Rule ID:** f315c173-354b-4ba5-a014-6e2f2d3f2764
- **Rule name:** Suspicious Module Load in Interactive User Processes (AN0282-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [collection] / [T1056]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id eq 7 | `7` |
| `image_path` | image_path regex .*\Q\explorer.exe\E$ | `C:\Windows\System32\explorer.exe` |
| `image_loaded` | image_loaded contains \Temp\ AND image_loaded not_contains \GoogleUpdate\ AND image_loaded not_contains \MicrosoftEdgeUpdate\ AND image_loaded not_contains \BraveUpdate\ AND image_loaded not_contains \Mozilla\updates\ AND image_loaded not_contains \Firefox\updates\ AND image_loaded not_contains \Update\\ AND image_loaded not_contains \NativeMessagingHosts\ AND image_loaded not_contains \native-messaging-hosts\ | `C:\Windows\System32\Temp\` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=7<br>`image_path`=C:\Windows\System32\explorer.exe<br>`image_loaded`=C:\Windows\System32\Temp\<br>`hostname`=ENG-WKS-717<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.108.207`
- alert `6eac6019897911c14982e10e6f54e79c` on lane `entity_key` = `10.42.108.207`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=7<br>`image_path`=C:\Windows\System32\cmd.exe\chrome.exe<br>`image_loaded`=C:\Windows\System32\amsi.dll\Users\Public\<br>`hostname`=OPS-WKS-718<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.109.207`
- alert `c1b7f7502ebe704873ed52345ddef853` on lane `entity_key` = `10.42.109.207`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_loaded not_contains \native-messaging-hosts\' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=7<br>`image_path`=C:\Windows\System32\explorer.exe<br>`image_loaded`=C:\Windows\System32\amsi.dll \native-messaging-hosts\<br>`hostname`=ENG-WKS-717<br>… | image_loaded=C:\Windows\System32\amsi.dll \native-messaging-hosts\ fails 'image_loaded not_contains \native-messaging-hosts\' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.108.207`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\explorer.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=7<br>`image_path`=C:\Windows\System32\explorer.exe.bak<br>`image_loaded`=C:\Windows\System32\Temp\<br>`hostname`=ENG-WKS-717<br>… | image_path=C:\Windows\System32\explorer.exe.bak fails 'image_path regex .*\Q\explorer.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.108.207`

