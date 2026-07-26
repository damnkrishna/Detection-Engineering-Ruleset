# Proof — RMM_TOOL_ABUSE

## Rule

- **Rule ID:** RMM_TOOL_ABUSE
- **Rule name:** Remote monitoring/management tool installed or contacted after initial access (Splunk: RMM Software story)
- **Rule shape:** SEQUENCE
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [suricata, wazuh]
- **Replay wire:** suricata on topic `replay-events-nids`
- **Correlation key:** `entity_key`
- **Window:** 3600s
- **Max gap:** _(not set)_
- **Stages:** 2
- **MITRE:** [TA0001, TA0002, TA0011, TA0003] / []
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains exploit | `ET MALWARE Observed Suspicious Outbound Connection exploit` |

### Stage 1

- Aggregate: `count`, threshold 2.0
- Events required: 2

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains teamviewer | `C:\Windows\System32 teamviewer` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 2 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection exploit<br>`hostname`=SEC-WKS-239<br>`agent_ip`=10.42.130.29<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +3600s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `signature_name`=C:\Windows\System32 teamviewer<br>`hostname`=SEC-WKS-239<br>`agent_ip`=10.42.130.29<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/2 |
| 3 | 2026-03-02T09:05:01.000Z | 1 | `signature_name`=C:\Windows\System32 teamviewer<br>`hostname`=SEC-WKS-239<br>`agent_ip`=10.42.130.29<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 2/2 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.130.29`
- alert `4b158149bd7a321d393e5524c4fb89e3` on lane `entity_key` = `10.42.130.29`, match mode `SEQUENCE`, 3 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 2 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 cve<br>`hostname`=FIN-WKS-240<br>`agent_ip`=10.42.131.29<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +3600s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T10:05:00.000Z | 1 | `signature_name`=C:\Users\j.mercer\AppData\Local\Temp screenconnect<br>`hostname`=FIN-WKS-240<br>`agent_ip`=10.42.131.29<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/2 |
| 3 | 2026-03-02T10:05:01.000Z | 1 | `signature_name`=C:\Users\j.mercer\AppData\Local\Temp screenconnect<br>`hostname`=FIN-WKS-240<br>`agent_ip`=10.42.131.29<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 2/2 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.131.29`
- alert `fd0089dfdccdd23a228b2a337db4ce84` on lane `entity_key` = `10.42.131.29`, match mode `SEQUENCE`, 3 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 1 | `signature_name`=C:\Windows\System32 teamviewer<br>`hostname`=SEC-WKS-239<br>`agent_ip`=10.42.130.29<br>`severity_id`=3<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 1 | `signature_name`=C:\Windows\System32 teamviewer<br>`hostname`=SEC-WKS-239<br>`agent_ip`=10.42.130.29<br>`severity_id`=3<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection exploit<br>`hostname`=SEC-WKS-239<br>`agent_ip`=10.42.130.29<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.130.29`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection exploit<br>`hostname`=SEC-WKS-239<br>`agent_ip`=10.42.130.29<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +3600s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:16:00.000Z | 1 | `signature_name`=C:\Windows\System32 teamviewer<br>`hostname`=SEC-WKS-239<br>`agent_ip`=10.42.130.29<br>`severity_id`=3<br>… | arrives 960s after the previous stage completed, past the 600s inter-stage bound, so the evaluator resets the partial match |
| 3 | 2026-03-02T09:16:01.000Z | 1 | `signature_name`=C:\Windows\System32 teamviewer<br>`hostname`=SEC-WKS-239<br>`agent_ip`=10.42.130.29<br>`severity_id`=3<br>… | arrives 961s after the previous stage completed, past the 600s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.130.29`

