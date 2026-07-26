# Proof — DATA_STAGING_LARGE_FILE

## Rule

- **Rule ID:** DATA_STAGING_LARGE_FILE
- **Rule name:** Bulk file archiving or compression (T1074.001) followed by large outbound transfer — pre-exfil staging behavior
- **Rule shape:** SEQUENCE
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [wazuh, suricata]
- **Replay wire:** wazuh on topic `replay-events-hids`
- **Correlation key:** `entity_key`
- **Window:** 7200s
- **Max gap:** _(not set)_
- **Stages:** 2
- **MITRE:** [TA0009, TA0010] / []
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 2.0
- Events required: 2

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic in_list [TA0009] | `TA0009` |
| `signature_name` | signature_name contains 7z | `Windows audit failure event 7z` |

### Stage 1

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 1800 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic in_list [TA0010] | `TA0010` |
| `signature_name` | signature_name contains high bytes out | `C:\Windows\System32 high bytes out` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 2 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `tactic`=TA0009<br>`signature_name`=Windows audit failure event 7z<br>`hostname`=FIN-WKS-620<br>`agent_ip`=10.42.11.148<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/2 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `tactic`=TA0009<br>`signature_name`=Windows audit failure event 7z<br>`hostname`=FIN-WKS-620<br>`agent_ip`=10.42.11.148<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/2 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +7200s (rule window) |
| 3 | 2026-03-02T09:05:01.000Z | 1 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 high bytes out<br>`hostname`=FIN-WKS-620<br>`agent_ip`=10.42.11.148<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `wazuh`, lane key = `10.42.11.148`
- alert `226006c1a2716a597dd69da3662584a3` on lane `entity_key` = `10.42.11.148`, match mode `SEQUENCE`, 3 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 2 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `tactic`=TA0009<br>`signature_name`=C:\Windows\System32 7zip<br>`hostname`=SEC-WKS-619<br>`agent_ip`=10.42.10.148<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/2 |
| 2 | 2026-03-02T10:00:01.000Z | 0 | `tactic`=TA0009<br>`signature_name`=C:\Windows\System32 7zip<br>`hostname`=SEC-WKS-619<br>`agent_ip`=10.42.10.148<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/2 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +7200s (rule window) |
| 3 | 2026-03-02T10:05:01.000Z | 1 | `tactic`=TA0010<br>`signature_name`=C:\Users\j.mercer\AppData\Local\Temp anomalous outbound<br>`hostname`=SEC-WKS-619<br>`agent_ip`=10.42.10.148<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `wazuh`, lane key = `10.42.10.148`
- alert `d90e93ac118568310547116433527a23` on lane `entity_key` = `10.42.10.148`, match mode `SEQUENCE`, 3 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 1 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 high bytes out<br>`hostname`=FIN-WKS-620<br>`agent_ip`=10.42.11.148<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `tactic`=TA0009<br>`signature_name`=Windows audit failure event 7z<br>`hostname`=FIN-WKS-620<br>`agent_ip`=10.42.11.148<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `tactic`=TA0009<br>`signature_name`=Windows audit failure event 7z<br>`hostname`=FIN-WKS-620<br>`agent_ip`=10.42.11.148<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `wazuh`, lane key = `10.42.11.148`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `tactic`=TA0009<br>`signature_name`=Windows audit failure event 7z<br>`hostname`=FIN-WKS-620<br>`agent_ip`=10.42.11.148<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/2 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `tactic`=TA0009<br>`signature_name`=Windows audit failure event 7z<br>`hostname`=FIN-WKS-620<br>`agent_ip`=10.42.11.148<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/2 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +7200s (rule window) |
| 3 | 2026-03-02T09:16:01.000Z | 1 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 high bytes out<br>`hostname`=FIN-WKS-620<br>`agent_ip`=10.42.11.148<br>… | arrives 960s after the previous stage completed, past the 600s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `wazuh`, lane key = `10.42.11.148`

