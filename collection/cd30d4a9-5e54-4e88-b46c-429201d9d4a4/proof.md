# Proof — cd30d4a9-5e54-4e88-b46c-429201d9d4a4

## Rule

- **Rule ID:** cd30d4a9-5e54-4e88-b46c-429201d9d4a4
- **Rule name:** Scripting Process Binding to LLMNR or NetBIOS Ports (AN1274-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [collection] / [T1557.001]
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
| `src_port` | src_port in_list [5355, 137] | `5355` |
| `image_path` | image_path regex .*\Q\python.exe\E$ AND image_path not_regex .*\Q\nbtstat.exe\E$ AND image_path not_regex .*\Q\netsh.exe\E$ AND image_path not_regex .*\Q\Wireshark.exe\E$ AND image_path not_regex .*\Q\tshark.exe\E$ AND image_path not_regex .*\Q\nmap.exe\E$ | `C:\Windows\System32\python.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`src_port`=5355<br>`image_path`=C:\Windows\System32\python.exe<br>`hostname`=SEC-WKS-604<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.95.43`
- alert `66412922b24f68740ef477aab6b139e6` on lane `entity_key` = `10.42.95.43`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=3<br>`src_port`=137<br>`image_path`=C:\Windows\System32\cmd.exe\powershell.exe<br>`hostname`=FIN-WKS-605<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.96.43`
- alert `c14e2fc678b4dfa06a47c7fde65d636b` on lane `entity_key` = `10.42.96.43`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\nmap.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`src_port`=5355<br>`image_path`=\nmap.exe<br>`hostname`=SEC-WKS-604<br>… | image_path=\nmap.exe fails 'image_path not_regex .*\Q\nmap.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.95.43`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'src_port in_list [5355, 137]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=3<br>`src_port`=5355.bak<br>`image_path`=C:\Windows\System32\python.exe<br>`hostname`=SEC-WKS-604<br>… | src_port=5355.bak fails 'src_port in_list [5355, 137]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.95.43`

