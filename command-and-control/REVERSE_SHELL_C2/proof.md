# Proof — REVERSE_SHELL_C2

## Rule

- **Rule ID:** REVERSE_SHELL_C2
- **Rule name:** Reverse shell established then C2 activity — active attacker on system
- **Rule shape:** SEQUENCE
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [suricata, wazuh]
- **Replay wire:** suricata on topic `replay-events-nids`
- **Correlation key:** `entity_key`
- **Window:** 1200s
- **Max gap:** _(not set)_
- **Stages:** 2
- **MITRE:** [TA0011] / [T1059]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains reverse shell | `ET MALWARE Observed Suspicious Outbound Connection reverse shell` |

### Stage 1

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 600 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains c2 | `C:\Windows\System32 c2` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection revers…<br>`hostname`=ENG-WKS-822<br>`agent_ip`=10.42.113.15<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1200s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `signature_name`=C:\Windows\System32 c2<br>`hostname`=ENG-WKS-822<br>`agent_ip`=10.42.113.15<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.113.15`
- alert `1d883b04459f10a5335522ab92d2625c` on lane `entity_key` = `10.42.113.15`, match mode `SEQUENCE`, 2 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 bash -i<br>`hostname`=HR-WKS-821<br>`agent_ip`=10.42.112.15<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1200s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T10:05:00.000Z | 1 | `signature_name`=C:\Users\j.mercer\AppData\Local\Temp c&c<br>`hostname`=HR-WKS-821<br>`agent_ip`=10.42.112.15<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.112.15`
- alert `1dcaa7b8c5b612ffc0afe4f50860b598` on lane `entity_key` = `10.42.112.15`, match mode `SEQUENCE`, 2 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 1 | `signature_name`=C:\Windows\System32 c2<br>`hostname`=ENG-WKS-822<br>`agent_ip`=10.42.113.15<br>`severity_id`=3<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection revers…<br>`hostname`=ENG-WKS-822<br>`agent_ip`=10.42.113.15<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.113.15`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection revers…<br>`hostname`=ENG-WKS-822<br>`agent_ip`=10.42.113.15<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1200s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:16:00.000Z | 1 | `signature_name`=C:\Windows\System32 c2<br>`hostname`=ENG-WKS-822<br>`agent_ip`=10.42.113.15<br>`severity_id`=3<br>… | arrives 960s after the previous stage completed, past the 600s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.113.15`

