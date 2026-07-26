# Proof — cb44046c-c24e-4773-9f2e-d8eb145f9b1a

## Rule

- **Rule ID:** cb44046c-c24e-4773-9f2e-d8eb145f9b1a
- **Rule name:** Scripting Process Outbound Connection Burst (AN0969-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [impact] / [T1498.001]
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
| `image_path` | image_path regex .*\Q\python.exe\E$ | `C:\Windows\System32\python.exe` |
| `dst_ip` | dst_ip not_starts_with 127. AND dst_ip not_starts_with 10. AND dst_ip not_starts_with 192.168. AND dst_ip not_starts_with 172.16. AND dst_ip not_starts_with ::1 | `198.51.100.24` |
| `parent_image` | parent_image not_regex .*\Q\explorer.exe\E$ AND parent_image not_regex .*\Q\mmc.exe\E$ | `C:\Windows` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`image_path`=C:\Windows\System32\python.exe<br>`dst_ip`=198.51.100.24<br>`parent_image`=C:\Windows<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.179.43`
- alert `3346ae809751bf02f1991d1b8fa4c7ea` on lane `entity_key` = `10.42.179.43`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=3<br>`image_path`=C:\Windows\System32\cmd.exe\powershell.exe<br>`dst_ip`=198.51.100.24<br>`parent_image`=C:\Windows\explorer.exe C:\Users\Public\export.dat<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.180.43`
- alert `4a121f8e2b48c1f67faddce6fa3aad26` on lane `entity_key` = `10.42.180.43`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'parent_image not_regex .*\Q\mmc.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`image_path`=C:\Windows\System32\python.exe<br>`dst_ip`=198.51.100.24<br>`parent_image`=\mmc.exe<br>… | parent_image=\mmc.exe fails 'parent_image not_regex .*\Q\mmc.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.179.43`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'dst_ip not_starts_with ::1' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`image_path`=C:\Windows\System32\python.exe<br>`dst_ip`=::1198.51.100.24<br>`parent_image`=C:\Windows<br>… | dst_ip=::1198.51.100.24 fails 'dst_ip not_starts_with ::1' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.179.43`

