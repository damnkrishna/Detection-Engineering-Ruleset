# Proof — NETWORK_TUNNEL_COVERT

## Rule

- **Rule ID:** NETWORK_TUNNEL_COVERT
- **Rule name:** Covert channel: protocol tunneling (DNS/ICMP/HTTP) or port forwarding tool — C2 traffic hiding inside legitimate protocols (T1572, T1090)
- **Rule shape:** SEQUENCE
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [suricata, wazuh]
- **Replay wire:** suricata on topic `replay-events-nids`
- **Correlation key:** `entity_key`
- **Window:** 3600s
- **Max gap:** _(not set)_
- **Stages:** 2
- **MITRE:** [TA0011, TA0010] / [T1572, T1095, T1090]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains plink.exe | `ET MALWARE Observed Suspicious Outbound Connection plink.exe` |

### Stage 1

- Aggregate: `count`, threshold 2.0
- `within_seconds` = 3600 (deadline for the next stage)
- Events required: 2

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic in_list [TA0011, TA0010] | `TA0010` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 2 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection plink.exe<br>`hostname`=SEC-WKS-174<br>`agent_ip`=10.42.65.136<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +3600s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `tactic`=TA0010<br>`hostname`=SEC-WKS-174<br>`agent_ip`=10.42.65.136<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/2 |
| 3 | 2026-03-02T09:05:01.000Z | 1 | `tactic`=TA0010<br>`hostname`=SEC-WKS-174<br>`agent_ip`=10.42.65.136<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 2/2 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.65.136`
- alert `371e63d1cea21f638be5212717ba38b2` on lane `entity_key` = `10.42.65.136`, match mode `SEQUENCE`, 3 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 2 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 chisel<br>`hostname`=OPS-WKS-173<br>`agent_ip`=10.42.64.136<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +3600s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T10:05:00.000Z | 1 | `tactic`=TA0011<br>`hostname`=OPS-WKS-173<br>`agent_ip`=10.42.64.136<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/2 |
| 3 | 2026-03-02T10:05:01.000Z | 1 | `tactic`=TA0011<br>`hostname`=OPS-WKS-173<br>`agent_ip`=10.42.64.136<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 2/2 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.64.136`
- alert `fd780695d772f4a8b862aa202cbf6bf1` on lane `entity_key` = `10.42.64.136`, match mode `SEQUENCE`, 3 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 1 | `tactic`=TA0010<br>`hostname`=SEC-WKS-174<br>`agent_ip`=10.42.65.136<br>`severity_id`=3<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 1 | `tactic`=TA0010<br>`hostname`=SEC-WKS-174<br>`agent_ip`=10.42.65.136<br>`severity_id`=3<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection plink.exe<br>`hostname`=SEC-WKS-174<br>`agent_ip`=10.42.65.136<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.65.136`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection plink.exe<br>`hostname`=SEC-WKS-174<br>`agent_ip`=10.42.65.136<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +3600s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:16:00.000Z | 1 | `tactic`=TA0010<br>`hostname`=SEC-WKS-174<br>`agent_ip`=10.42.65.136<br>`severity_id`=3<br>… | arrives 960s after the previous stage completed, past the 600s inter-stage bound, so the evaluator resets the partial match |
| 3 | 2026-03-02T09:16:01.000Z | 1 | `tactic`=TA0010<br>`hostname`=SEC-WKS-174<br>`agent_ip`=10.42.65.136<br>`severity_id`=3<br>… | arrives 961s after the previous stage completed, past the 600s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.65.136`

