# Proof — f023d881-819a-44f2-9ca0-80ef522f0030

## Rule

- **Rule ID:** f023d881-819a-44f2-9ca0-80ef522f0030
- **Rule name:** Hook Evasion via Non-Standard System DLL Load (AN1465-A)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [execution] / [T1106]
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
| `image_loaded` | image_loaded regex .*\Q\ntdll.dll\E$ AND image_loaded not_starts_with C:\Windows\System32\ AND image_loaded not_starts_with C:\Windows\SysWOW64\ AND image_loaded not_starts_with C:\Windows\WinSxS\ | `C:\Users\j.mercer\AppData\Local\Temp\ntdll.dll` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=7<br>`image_loaded`=C:\Users\j.mercer\AppData\Local\Temp\ntdll.dll<br>`hostname`=SEC-WKS-324<br>`agent_ip`=10.42.15.12<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.15.12`
- alert `9f6408032c2c60bf60b249aa84b11620` on lane `entity_key` = `10.42.15.12`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=7<br>`image_loaded`=C:\Users\j.mercer\AppData\Local\Temp\kernel32.dll<br>`hostname`=FIN-WKS-325<br>`agent_ip`=10.42.16.12<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.16.12`
- alert `d19c169d33583a6e5ed4b86c01615845` on lane `entity_key` = `10.42.16.12`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_loaded not_starts_with C:\Windows\WinSxS\' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=7<br>`image_loaded`=C:\Windows\WinSxS\C:\Windows\System32\amsi.dll<br>`hostname`=SEC-WKS-324<br>`agent_ip`=10.42.15.12<br>… | image_loaded=C:\Windows\WinSxS\C:\Windows\System32\amsi.dll fails 'image_loaded not_starts_with C:\Windows\WinSxS\' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.15.12`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'event_id eq 7' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=7.bak<br>`image_loaded`=C:\Users\j.mercer\AppData\Local\Temp\ntdll.dll<br>`hostname`=SEC-WKS-324<br>`agent_ip`=10.42.15.12<br>… | event_id=7.bak fails 'event_id eq 7' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.15.12`

