# Proof — f8041fd7-61e2-4cb0-ab40-24d5cc7a7938

## Rule

- **Rule ID:** f8041fd7-61e2-4cb0-ab40-24d5cc7a7938
- **Rule name:** High Connection Burst to Web Server Port (AN1165-A)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [impact] / [T1499.003]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id eq 3 | `3` |
| `dst_port` | dst_port in_list [80, 443, 8080, 8443] | `80` |
| `image_path` | image_path not_regex .*\Q\chrome.exe\E$ AND image_path not_regex .*\Q\firefox.exe\E$ AND image_path not_regex .*\Q\msedge.exe\E$ AND image_path not_regex .*\Q\w3wp.exe\E$ AND image_path not_regex .*\Q\nginx.exe\E$ AND image_path not_regex .*\Q\httpd.exe\E$ AND image_path not_regex .*\Q\tomcat.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`dst_port`=80<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=HR-WKS-201<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.192.203`
- alert `151132709a72623e1a17aaf40af52a4a` on lane `entity_key` = `10.42.192.203`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=3<br>`dst_port`=443<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=ENG-WKS-202<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.193.203`
- alert `3d9741268c4d9ea0fb231b6b7e980aa0` on lane `entity_key` = `10.42.193.203`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\tomcat.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`dst_port`=80<br>`image_path`=\tomcat.exe<br>`hostname`=HR-WKS-201<br>… | image_path=\tomcat.exe fails 'image_path not_regex .*\Q\tomcat.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.192.203`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'dst_port in_list [80, 443, 8080, 8443]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`dst_port`=80.bak<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=HR-WKS-201<br>… | dst_port=80.bak fails 'dst_port in_list [80, 443, 8080, 8443]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.192.203`

