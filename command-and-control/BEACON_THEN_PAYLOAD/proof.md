# Proof — BEACON_THEN_PAYLOAD

## Rule

- **Rule ID:** BEACON_THEN_PAYLOAD
- **Rule name:** C2 beaconing → tool download → execution (full compromise chain)
- **Rule shape:** SEQUENCE
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [suricata, wazuh]
- **Replay wire:** suricata on topic `replay-events-nids`
- **Correlation key:** `entity_key`
- **Window:** 3600s
- **Max gap:** _(not set)_
- **Stages:** 3
- **MITRE:** [TA0011, TA0002] / [T1105]
- **Behavioral constraints:** declared on the rule

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains beacon | `ET MALWARE Observed Suspicious Outbound Connection beacon` |

### Stage 1

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains bitsadmin | `C:\Windows\System32 bitsadmin` |

### Stage 2

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic in_list [TA0002] | `TA0002` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s) → stage 2 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection beacon<br>`hostname`=FIN-WKS-610<br>`agent_ip`=10.42.101.16<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +3600s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `signature_name`=C:\Windows\System32 bitsadmin<br>`hostname`=FIN-WKS-610<br>`agent_ip`=10.42.101.16<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T09:10:00.000Z | 2 | `tactic`=TA0002<br>`hostname`=FIN-WKS-610<br>`agent_ip`=10.42.101.16<br>`severity_id`=3<br>… | satisfies every condition of stage 2; increments the count aggregate to 1/1 — the threshold event that completes stage 2 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.101.16`
- alert `14f655d0ece82cae7f69983540df51db` on lane `entity_key` = `10.42.101.16`, match mode `SEQUENCE`, 3 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s) → stage 2 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 periodic<br>`hostname`=HR-WKS-611<br>`agent_ip`=10.42.102.16<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +3600s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T10:05:00.000Z | 1 | `signature_name`=C:\Users\j.mercer\AppData\Local\Temp wget<br>`hostname`=HR-WKS-611<br>`agent_ip`=10.42.102.16<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T10:10:00.000Z | 2 | `tactic`=TA0002<br>`hostname`=HR-WKS-611<br>`agent_ip`=10.42.102.16<br>`severity_id`=3<br>… | satisfies every condition of stage 2; increments the count aggregate to 1/1 — the threshold event that completes stage 2 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.102.16`
- alert `4af449a34285ea0cc9280c4616a9ec08` on lane `entity_key` = `10.42.102.16`, match mode `SEQUENCE`, 3 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 2 | `tactic`=TA0002<br>`hostname`=FIN-WKS-610<br>`agent_ip`=10.42.101.16<br>`severity_id`=3<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection beacon<br>`hostname`=FIN-WKS-610<br>`agent_ip`=10.42.101.16<br>`severity_id`=3<br>… | completes stage 0, but the stage-2 evidence has already passed and is never replayed |
| 3 | 2026-03-02T09:00:02.000Z | 1 | `signature_name`=C:\Windows\System32 bitsadmin<br>`hostname`=FIN-WKS-610<br>`agent_ip`=10.42.101.16<br>`severity_id`=3<br>… | completes stage 0, but the stage-2 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.101.16`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection beacon<br>`hostname`=FIN-WKS-610<br>`agent_ip`=10.42.101.16<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +3600s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `signature_name`=C:\Windows\System32 bitsadmin<br>`hostname`=FIN-WKS-610<br>`agent_ip`=10.42.101.16<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T09:21:00.000Z | 2 | `tactic`=TA0002<br>`hostname`=FIN-WKS-610<br>`agent_ip`=10.42.101.16<br>`severity_id`=3<br>… | arrives 960s after the previous stage completed, past the 600s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.101.16`

