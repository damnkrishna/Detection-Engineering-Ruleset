# Proof — STAGED_CLOUD_UPLOAD

## Rule

- **Rule ID:** STAGED_CLOUD_UPLOAD
- **Rule name:** File collection on endpoint (HIDS) followed by cloud sync client making large outbound upload (Zeek) — T1567.002 exfil over cloud storage API evading DLP; cross-sensor confirmation
- **Rule shape:** SEQUENCE
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [wazuh, zeek]
- **Replay wire:** wazuh on topic `replay-events-hids`
- **Correlation key:** `entity_key`
- **Window:** 3600s
- **Max gap:** _(not set)_
- **Stages:** 2
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
| `source` | source in_list [HIDS] | `HIDS` |
| `signature_name` | signature_name contains 7z | `Windows audit failure event 7z` |

### Stage 1

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 1800 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic in_list [TA0010] | `TA0010` |
| `source` | source in_list [ZEEK] | `ZEEK` |
| `signature_name` | signature_name contains sharepoint | `C:\Windows\System32 sharepoint` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `tactic`=TA0009<br>`source`=HIDS<br>`signature_name`=Windows audit failure event 7z<br>`hostname`=ENG-WKS-267<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +3600s (rule window) |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `tactic`=TA0010<br>`source`=ZEEK<br>`signature_name`=C:\Windows\System32 sharepoint<br>`hostname`=ENG-WKS-267<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `wazuh`, lane key = `10.42.58.181`
- alert `fba761dc2e2a1c6eef74a0feffca843c` on lane `entity_key` = `10.42.58.181`, match mode `SEQUENCE`, 2 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `tactic`=TA0009<br>`source`=HIDS<br>`signature_name`=C:\Windows\System32 zip<br>`hostname`=OPS-WKS-268<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +3600s (rule window) |
| 2 | 2026-03-02T10:05:00.000Z | 1 | `tactic`=TA0010<br>`source`=ZEEK<br>`signature_name`=C:\Users\j.mercer\AppData\Local\Temp dropbox<br>`hostname`=OPS-WKS-268<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `wazuh`, lane key = `10.42.59.181`
- alert `6e03c026d53b3ec13cc3ebb1d726b2c8` on lane `entity_key` = `10.42.59.181`, match mode `SEQUENCE`, 2 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 1 | `tactic`=TA0010<br>`source`=ZEEK<br>`signature_name`=C:\Windows\System32 sharepoint<br>`hostname`=ENG-WKS-267<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `tactic`=TA0009<br>`source`=HIDS<br>`signature_name`=Windows audit failure event 7z<br>`hostname`=ENG-WKS-267<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `wazuh`, lane key = `10.42.58.181`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `tactic`=TA0009<br>`source`=HIDS<br>`signature_name`=Windows audit failure event 7z<br>`hostname`=ENG-WKS-267<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +3600s (rule window) |
| 2 | 2026-03-02T09:16:00.000Z | 1 | `tactic`=TA0010<br>`source`=ZEEK<br>`signature_name`=C:\Windows\System32 sharepoint<br>`hostname`=ENG-WKS-267<br>… | arrives 960s after the previous stage completed, past the 600s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `wazuh`, lane key = `10.42.58.181`

