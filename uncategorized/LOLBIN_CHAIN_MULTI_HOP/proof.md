# Proof — LOLBIN_CHAIN_MULTI_HOP

## Rule

- **Rule ID:** LOLBIN_CHAIN_MULTI_HOP
- **Rule name:** Multi-hop LOLBin proxy chain: script interpreter (mshta/wscript) spawns signed-binary proxy (regsvr32/rundll32/InstallUtil) which spawns shell or C2 — T1218 proxy chaining for AppLocker/WDAC bypass
- **Rule shape:** SEQUENCE
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [wazuh]
- **Replay wire:** wazuh on topic `replay-events-hids`
- **Correlation key:** `entity_key`
- **Window:** 1800s
- **Max gap:** _(not set)_
- **Stages:** 3
- **MITRE:** [TA0002, TA0003, TA0011] / [T1218]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains mshta.exe | `Windows audit failure event mshta.exe` |

### Stage 1

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 120 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains rundll32.exe | `C:\Windows\System32 rundll32.exe` |

### Stage 2

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic in_list [TA0002, TA0003, TA0011] | `TA0011` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s) → stage 2 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=Windows audit failure event mshta.exe<br>`hostname`=SEC-WKS-109<br>`agent_ip`=10.42.200.195<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1800s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `signature_name`=C:\Windows\System32 rundll32.exe<br>`hostname`=SEC-WKS-109<br>`agent_ip`=10.42.200.195<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T09:06:00.000Z | 2 | `tactic`=TA0011<br>`hostname`=SEC-WKS-109<br>`agent_ip`=10.42.200.195<br>`severity_id`=3<br>… | satisfies every condition of stage 2; increments the count aggregate to 1/1 — the threshold event that completes stage 2 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `wazuh`, lane key = `10.42.200.195`
- alert `9007db20668d3ac7282447754da922d2` on lane `entity_key` = `10.42.200.195`, match mode `SEQUENCE`, 3 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s) → stage 2 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 wscript.exe<br>`hostname`=OPS-WKS-108<br>`agent_ip`=10.42.199.195<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1800s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T10:05:00.000Z | 1 | `signature_name`=C:\Users\j.mercer\AppData\Local\Temp InstallUtil.exe<br>`hostname`=OPS-WKS-108<br>`agent_ip`=10.42.199.195<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T10:06:00.000Z | 2 | `tactic`=TA0002<br>`hostname`=OPS-WKS-108<br>`agent_ip`=10.42.199.195<br>`severity_id`=3<br>… | satisfies every condition of stage 2; increments the count aggregate to 1/1 — the threshold event that completes stage 2 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `wazuh`, lane key = `10.42.199.195`
- alert `d276baf9b8dc13b4001d86501696c005` on lane `entity_key` = `10.42.199.195`, match mode `SEQUENCE`, 3 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 2 | `tactic`=TA0011<br>`hostname`=SEC-WKS-109<br>`agent_ip`=10.42.200.195<br>`severity_id`=3<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=Windows audit failure event mshta.exe<br>`hostname`=SEC-WKS-109<br>`agent_ip`=10.42.200.195<br>`severity_id`=3<br>… | completes stage 0, but the stage-2 evidence has already passed and is never replayed |
| 3 | 2026-03-02T09:00:02.000Z | 1 | `signature_name`=C:\Windows\System32 rundll32.exe<br>`hostname`=SEC-WKS-109<br>`agent_ip`=10.42.200.195<br>`severity_id`=3<br>… | completes stage 0, but the stage-2 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `wazuh`, lane key = `10.42.200.195`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=Windows audit failure event mshta.exe<br>`hostname`=SEC-WKS-109<br>`agent_ip`=10.42.200.195<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1800s (rule window); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `signature_name`=C:\Windows\System32 rundll32.exe<br>`hostname`=SEC-WKS-109<br>`agent_ip`=10.42.200.195<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T09:09:00.000Z | 2 | `tactic`=TA0011<br>`hostname`=SEC-WKS-109<br>`agent_ip`=10.42.200.195<br>`severity_id`=3<br>… | arrives 240s after the previous stage completed, past the 120s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `wazuh`, lane key = `10.42.200.195`

