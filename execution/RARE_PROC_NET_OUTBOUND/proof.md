# Proof — RARE_PROC_NET_OUTBOUND

## Rule

- **Rule ID:** RARE_PROC_NET_OUTBOUND
- **Rule name:** Non-browser signed-binary process makes first-ever outbound connection on non-standard port — implant or LOLBin C2 first-time activation (T1071, T1095)
- **Rule shape:** SEQUENCE
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [wazuh, zeek]
- **Replay wire:** wazuh on topic `replay-events-hids`
- **Correlation key:** `entity_key`
- **Window:** 1800s
- **Max gap:** _(not set)_
- **Stages:** 2
- **MITRE:** [TA0002, TA0011] / []
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic in_list [TA0002] | `TA0002` |
| `source` | source in_list [HIDS] | `HIDS` |
| `signature_name` | signature_name contains mshta.exe | `Windows audit failure event mshta.exe` |

### Stage 1

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic in_list [TA0011] | `TA0011` |
| `source` | source in_list [ZEEK] | `ZEEK` |
| `signature_name` | signature_name contains non-standard port | `C:\Windows\System32 non-standard port` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `tactic`=TA0002<br>`source`=HIDS<br>`signature_name`=Windows audit failure event mshta.exe<br>`hostname`=ENG-WKS-257<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1800s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `tactic`=TA0011<br>`source`=ZEEK<br>`signature_name`=C:\Windows\System32 non-standard port<br>`hostname`=ENG-WKS-257<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `wazuh`, lane key = `10.42.148.105`
- alert `ea9025352a0df71ae01b5728ee5a6ca2` on lane `entity_key` = `10.42.148.105`, match mode `SEQUENCE`, 2 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `tactic`=TA0002<br>`source`=HIDS<br>`signature_name`=C:\Windows\System32 wscript.exe<br>`hostname`=OPS-WKS-258<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1800s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T10:05:00.000Z | 1 | `tactic`=TA0011<br>`source`=ZEEK<br>`signature_name`=C:\Users\j.mercer\AppData\Local\Temp outbound connection<br>`hostname`=OPS-WKS-258<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `wazuh`, lane key = `10.42.149.105`
- alert `11889e274c655e681a352a81673a306c` on lane `entity_key` = `10.42.149.105`, match mode `SEQUENCE`, 2 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 1 | `tactic`=TA0011<br>`source`=ZEEK<br>`signature_name`=C:\Windows\System32 non-standard port<br>`hostname`=ENG-WKS-257<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `tactic`=TA0002<br>`source`=HIDS<br>`signature_name`=Windows audit failure event mshta.exe<br>`hostname`=ENG-WKS-257<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `wazuh`, lane key = `10.42.148.105`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `tactic`=TA0002<br>`source`=HIDS<br>`signature_name`=Windows audit failure event mshta.exe<br>`hostname`=ENG-WKS-257<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1800s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:16:00.000Z | 1 | `tactic`=TA0011<br>`source`=ZEEK<br>`signature_name`=C:\Windows\System32 non-standard port<br>`hostname`=ENG-WKS-257<br>… | arrives 960s after the previous stage completed, past the 600s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `wazuh`, lane key = `10.42.148.105`

