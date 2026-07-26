# Proof — WEB_SHELL_DEPLOY

## Rule

- **Rule ID:** WEB_SHELL_DEPLOY
- **Rule name:** Web server exploitation then web shell deployed and executed (Splunk: Web Shell story)
- **Rule shape:** SEQUENCE
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [suricata, wazuh]
- **Replay wire:** suricata on topic `replay-events-nids`
- **Correlation key:** `entity_key`
- **Window:** 1200s
- **Max gap:** _(not set)_
- **Stages:** 2
- **MITRE:** [TA0001, TA0002] / []
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains POST | `ET MALWARE Observed Suspicious Outbound Connection POST` |

### Stage 1

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains powershell | `C:\Windows\System32 powershell` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection POST<br>`hostname`=OPS-WKS-348<br>`agent_ip`=10.42.139.159<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1200s (rule window) |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `signature_name`=C:\Windows\System32 powershell<br>`hostname`=OPS-WKS-348<br>`agent_ip`=10.42.139.159<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.139.159`
- alert `f5ad536ad87de2d980aa8bd2e988e147` on lane `entity_key` = `10.42.139.159`, match mode `SEQUENCE`, 2 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 file upload<br>`hostname`=ENG-WKS-347<br>`agent_ip`=10.42.138.159<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1200s (rule window) |
| 2 | 2026-03-02T10:05:00.000Z | 1 | `signature_name`=C:\Users\j.mercer\AppData\Local\Temp bash<br>`hostname`=ENG-WKS-347<br>`agent_ip`=10.42.138.159<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.138.159`
- alert `aa04df888182a4e5d9a946c576ed903f` on lane `entity_key` = `10.42.138.159`, match mode `SEQUENCE`, 2 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 1 | `signature_name`=C:\Windows\System32 powershell<br>`hostname`=OPS-WKS-348<br>`agent_ip`=10.42.139.159<br>`severity_id`=3<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection POST<br>`hostname`=OPS-WKS-348<br>`agent_ip`=10.42.139.159<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.139.159`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection POST<br>`hostname`=OPS-WKS-348<br>`agent_ip`=10.42.139.159<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1200s (rule window) |
| 2 | 2026-03-02T09:16:00.000Z | 1 | `signature_name`=C:\Windows\System32 powershell<br>`hostname`=OPS-WKS-348<br>`agent_ip`=10.42.139.159<br>`severity_id`=3<br>… | arrives 960s after the previous stage completed, past the 600s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.139.159`

