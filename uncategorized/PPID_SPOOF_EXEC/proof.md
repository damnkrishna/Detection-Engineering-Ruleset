# Proof — PPID_SPOOF_EXEC

## Rule

- **Rule ID:** PPID_SPOOF_EXEC
- **Rule name:** Process spawned with spoofed parent PID to masquerade as legitimate child — EDR/behavioral bypass used by Cobalt Strike, custom loaders, and PPID injection tooling (T1134.004)
- **Rule shape:** SEQUENCE
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [wazuh]
- **Replay wire:** wazuh on topic `replay-events-hids`
- **Correlation key:** `entity_key`
- **Window:** 1800s
- **Max gap:** _(not set)_
- **Stages:** 2
- **MITRE:** [TA0002, TA0003, TA0011, TA0004] / [T1134.004]
- **Behavioral constraints:** declared on the rule

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains ppid spoofing | `Windows audit failure event ppid spoofing` |

### Stage 1

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic in_list [TA0002, TA0003, TA0011, TA0004] | `TA0003` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=Windows audit failure event ppid spoofing<br>`hostname`=FIN-WKS-590<br>`agent_ip`=10.42.81.129<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1800s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on; runs an execution-policy bypass out of a staging directory, which is what marks the process suspicious — the rule declares require_suspicious_process |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `tactic`=TA0003<br>`hostname`=FIN-WKS-590<br>`agent_ip`=10.42.81.129<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `wazuh`, lane key = `10.42.81.129`
- alert `b2700b682e2f500bbd3179c3c11f0653` on lane `entity_key` = `10.42.81.129`, match mode `SEQUENCE`, 2 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 parent process mismatch<br>`hostname`=SEC-WKS-589<br>`agent_ip`=10.42.80.129<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1800s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on; runs an execution-policy bypass out of a staging directory, which is what marks the process suspicious — the rule declares require_suspicious_process |
| 2 | 2026-03-02T10:05:00.000Z | 1 | `tactic`=TA0011<br>`hostname`=SEC-WKS-589<br>`agent_ip`=10.42.80.129<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `wazuh`, lane key = `10.42.80.129`
- alert `d22ac6767d3ec00f626e9c892b002fb2` on lane `entity_key` = `10.42.80.129`, match mode `SEQUENCE`, 2 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 1 | `tactic`=TA0003<br>`hostname`=FIN-WKS-590<br>`agent_ip`=10.42.81.129<br>`severity_id`=3<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=Windows audit failure event ppid spoofing<br>`hostname`=FIN-WKS-590<br>`agent_ip`=10.42.81.129<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `wazuh`, lane key = `10.42.81.129`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=Windows audit failure event ppid spoofing<br>`hostname`=FIN-WKS-590<br>`agent_ip`=10.42.81.129<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1800s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on; runs an execution-policy bypass out of a staging directory, which is what marks the process suspicious — the rule declares require_suspicious_process |
| 2 | 2026-03-02T09:16:00.000Z | 1 | `tactic`=TA0003<br>`hostname`=FIN-WKS-590<br>`agent_ip`=10.42.81.129<br>`severity_id`=3<br>… | arrives 960s after the previous stage completed, past the 600s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `wazuh`, lane key = `10.42.81.129`

