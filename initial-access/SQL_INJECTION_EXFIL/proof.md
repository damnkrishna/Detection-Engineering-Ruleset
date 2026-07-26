# Proof — SQL_INJECTION_EXFIL

## Rule

- **Rule ID:** SQL_INJECTION_EXFIL
- **Rule name:** SQL injection followed by data exfiltration (Splunk: Web Application Attack story)
- **Rule shape:** SEQUENCE
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [suricata]
- **Replay wire:** suricata on topic `replay-events-nids`
- **Correlation key:** `entity_key`
- **Window:** 1800s
- **Max gap:** _(not set)_
- **Stages:** 2
- **MITRE:** [TA0001, TA0010] / []
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains SQL injection | `ET MALWARE Observed Suspicious Outbound Connection SQL injection` |

### Stage 1

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains data exfil | `C:\Windows\System32 data exfil` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection SQL in…<br>`hostname`=SEC-WKS-644<br>`agent_ip`=10.42.35.11<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1800s (rule window) |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `signature_name`=C:\Windows\System32 data exfil<br>`hostname`=SEC-WKS-644<br>`agent_ip`=10.42.35.11<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.35.11`
- alert `309ac8f55313122296b56181b36ed4ab` on lane `entity_key` = `10.42.35.11`, match mode `SEQUENCE`, 2 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 UNION SELECT<br>`hostname`=FIN-WKS-645<br>`agent_ip`=10.42.36.11<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1800s (rule window) |
| 2 | 2026-03-02T10:05:00.000Z | 1 | `signature_name`=C:\Users\j.mercer\AppData\Local\Temp SELECT<br>`hostname`=FIN-WKS-645<br>`agent_ip`=10.42.36.11<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.36.11`
- alert `d5f3fadaff91e898e973d84111863bca` on lane `entity_key` = `10.42.36.11`, match mode `SEQUENCE`, 2 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 1 | `signature_name`=C:\Windows\System32 data exfil<br>`hostname`=SEC-WKS-644<br>`agent_ip`=10.42.35.11<br>`severity_id`=3<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection SQL in…<br>`hostname`=SEC-WKS-644<br>`agent_ip`=10.42.35.11<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.35.11`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection SQL in…<br>`hostname`=SEC-WKS-644<br>`agent_ip`=10.42.35.11<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1800s (rule window) |
| 2 | 2026-03-02T09:16:00.000Z | 1 | `signature_name`=C:\Windows\System32 data exfil<br>`hostname`=SEC-WKS-644<br>`agent_ip`=10.42.35.11<br>`severity_id`=3<br>… | arrives 960s after the previous stage completed, past the 600s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.35.11`

