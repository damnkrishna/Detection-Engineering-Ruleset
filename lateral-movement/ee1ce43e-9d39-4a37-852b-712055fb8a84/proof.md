# Proof — ee1ce43e-9d39-4a37-852b-712055fb8a84

## Rule

- **Rule ID:** ee1ce43e-9d39-4a37-852b-712055fb8a84
- **Rule name:** Lateral Movement - Script Host Initiating Outbound SMTP Connection (AN0147)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [lateral-movement] / [T1534, T1566.002]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `dst_port` | dst_port in_list [25, 465, 587] | `25` |
| `initiated` | initiated eq true | `true` |
| `image_path` | image_path regex .*\Q\powershell.exe\E$ | `C:\Windows\System32\powershell.exe` |
| `dst_ip` | dst_ip not_in_list [127.0.0.1, ::1] | `198.51.100.24` |
| `username` | username not_contains NT AUTHORITY\SYSTEM AND username not_contains NT AUTHORITY\NETWORK SERVICE AND username not_contains NT AUTHORITY\LOCAL SERVICE AND username not_contains SYSTEM | `CORP\j.mercer` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `dst_port`=25<br>`initiated`=true<br>`image_path`=C:\Windows\System32\powershell.exe<br>`dst_ip`=198.51.100.24<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `CORP\j.mercer`
- alert `21f83834a7dfb33a3c2cbf601f2898cc` on lane `entity_key` = `CORP\j.mercer`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `dst_port`=465<br>`initiated`=true<br>`image_path`=C:\Windows\System32\cmd.exe\pwsh.exe<br>`dst_ip`=198.51.100.24<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `CORP\j.mercer`
- alert `de02b596e60d04fbf2e75d6062766cf1` on lane `entity_key` = `CORP\j.mercer`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'username not_contains SYSTEM' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `dst_port`=25<br>`initiated`=true<br>`image_path`=C:\Windows\System32\powershell.exe<br>`dst_ip`=198.51.100.24<br>… | username=CORP\j.mercer SYSTEM fails 'username not_contains SYSTEM' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `CORP\j.mercer SYSTEM`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'dst_ip not_in_list [127.0.0.1, ::1]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `dst_port`=25<br>`initiated`=true<br>`image_path`=C:\Windows\System32\powershell.exe<br>`dst_ip`=127.0.0.1<br>… | dst_ip=127.0.0.1 fails 'dst_ip not_in_list [127.0.0.1, ::1]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `CORP\j.mercer`

