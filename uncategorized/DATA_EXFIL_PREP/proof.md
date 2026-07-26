# Proof — DATA_EXFIL_PREP

## Rule

- **Rule ID:** DATA_EXFIL_PREP
- **Rule name:** Collection → staging → exfiltration (Splunk: Data Exfiltration story)
- **Rule shape:** SEQUENCE
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [suricata, wazuh]
- **Replay wire:** suricata on topic `replay-events-nids`
- **Correlation key:** `entity_key`
- **Window:** 7200s
- **Max gap:** _(not set)_
- **Stages:** 3
- **MITRE:** [TA0009, TA0010] / []
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic in_list [TA0009] | `TA0009` |

### Stage 1

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic in_list [TA0009] | `TA0009` |
| `signature_name` | signature_name contains WinRAR | `C:\Windows\System32 WinRAR` |

### Stage 2

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic in_list [TA0010] | `TA0010` |
| `signature_name` | signature_name contains transfer | `C:\Users\j.mercer\AppData\Local\Temp transfer` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s) → stage 2 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `tactic`=TA0009<br>`hostname`=FIN-WKS-530<br>`agent_ip`=10.42.121.158<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +7200s (rule window) |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `tactic`=TA0009<br>`signature_name`=C:\Windows\System32 WinRAR<br>`hostname`=FIN-WKS-530<br>`agent_ip`=10.42.121.158<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T09:10:00.000Z | 2 | `tactic`=TA0010<br>`signature_name`=C:\Users\j.mercer\AppData\Local\Temp transfer<br>`hostname`=FIN-WKS-530<br>`agent_ip`=10.42.121.158<br>… | satisfies every condition of stage 2; increments the count aggregate to 1/1 — the threshold event that completes stage 2 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.121.158`
- alert `73369575e3fd5af7a5189a7378176cae` on lane `entity_key` = `10.42.121.158`, match mode `SEQUENCE`, 3 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s) → stage 2 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `tactic`=TA0009<br>`hostname`=HR-WKS-531<br>`agent_ip`=10.42.122.158<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +7200s (rule window) |
| 2 | 2026-03-02T10:05:00.000Z | 1 | `tactic`=TA0009<br>`signature_name`=C:\Users\j.mercer\AppData\Local\Temp zip<br>`hostname`=HR-WKS-531<br>`agent_ip`=10.42.122.158<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T10:10:00.000Z | 2 | `tactic`=TA0010<br>`signature_name`=C:\Windows\SysWOW64 dns query<br>`hostname`=HR-WKS-531<br>`agent_ip`=10.42.122.158<br>… | satisfies every condition of stage 2; increments the count aggregate to 1/1 — the threshold event that completes stage 2 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.122.158`
- alert `50cdbefab0dcf82e0582c5facd7e68fa` on lane `entity_key` = `10.42.122.158`, match mode `SEQUENCE`, 3 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 2 | `tactic`=TA0010<br>`signature_name`=C:\Users\j.mercer\AppData\Local\Temp transfer<br>`hostname`=FIN-WKS-530<br>`agent_ip`=10.42.121.158<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `tactic`=TA0009<br>`hostname`=FIN-WKS-530<br>`agent_ip`=10.42.121.158<br>`severity_id`=3<br>… | completes stage 0, but the stage-2 evidence has already passed and is never replayed |
| 3 | 2026-03-02T09:00:02.000Z | 1 | `tactic`=TA0009<br>`signature_name`=C:\Windows\System32 WinRAR<br>`hostname`=FIN-WKS-530<br>`agent_ip`=10.42.121.158<br>… | completes stage 0, but the stage-2 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.121.158`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `tactic`=TA0009<br>`hostname`=FIN-WKS-530<br>`agent_ip`=10.42.121.158<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +7200s (rule window) |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `tactic`=TA0009<br>`signature_name`=C:\Windows\System32 WinRAR<br>`hostname`=FIN-WKS-530<br>`agent_ip`=10.42.121.158<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T09:21:00.000Z | 2 | `tactic`=TA0010<br>`signature_name`=C:\Users\j.mercer\AppData\Local\Temp transfer<br>`hostname`=FIN-WKS-530<br>`agent_ip`=10.42.121.158<br>… | arrives 960s after the previous stage completed, past the 600s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.121.158`

