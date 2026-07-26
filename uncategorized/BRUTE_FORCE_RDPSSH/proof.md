# Proof — BRUTE_FORCE_RDPSSH

## Rule

- **Rule ID:** BRUTE_FORCE_RDPSSH
- **Rule name:** Brute force against RDP/SSH/VPN followed by successful authentication
- **Rule shape:** SEQUENCE
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [suricata, wazuh]
- **Replay wire:** suricata on topic `replay-events-nids`
- **Correlation key:** `entity_key`
- **Window:** 3600s
- **Max gap:** _(not set)_
- **Stages:** 2
- **MITRE:** [] / []
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 3.0
- Events required: 3

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains RDP brute | `ET MALWARE Observed Suspicious Outbound Connection RDP brute` |

### Stage 1

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 3600 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains accepted password | `C:\Windows\System32 accepted password` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 3 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection RDP brute<br>`hostname`=SEC-WKS-674<br>`agent_ip`=10.42.165.200<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/3 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection RDP brute<br>`hostname`=SEC-WKS-674<br>`agent_ip`=10.42.165.200<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/3 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection RDP brute<br>`hostname`=SEC-WKS-674<br>`agent_ip`=10.42.165.200<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/3 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +3600s (rule window) |
| 4 | 2026-03-02T09:05:02.000Z | 1 | `signature_name`=C:\Windows\System32 accepted password<br>`hostname`=SEC-WKS-674<br>`agent_ip`=10.42.165.200<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 4 of 4 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.165.200`
- alert `1e178f1dab8567f68518d8f6fc703b76` on lane `entity_key` = `10.42.165.200`, match mode `SEQUENCE`, 4 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 3 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 SSH brute<br>`hostname`=FIN-WKS-675<br>`agent_ip`=10.42.166.200<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/3 |
| 2 | 2026-03-02T10:00:01.000Z | 0 | `signature_name`=C:\Windows\System32 SSH brute<br>`hostname`=FIN-WKS-675<br>`agent_ip`=10.42.166.200<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/3 |
| 3 | 2026-03-02T10:00:02.000Z | 0 | `signature_name`=C:\Windows\System32 SSH brute<br>`hostname`=FIN-WKS-675<br>`agent_ip`=10.42.166.200<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/3 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +3600s (rule window) |
| 4 | 2026-03-02T10:05:02.000Z | 1 | `signature_name`=C:\Users\j.mercer\AppData\Local\Temp session opened<br>`hostname`=FIN-WKS-675<br>`agent_ip`=10.42.166.200<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 4 of 4 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.166.200`
- alert `c858a691f35650e91d367f281b511ef4` on lane `entity_key` = `10.42.166.200`, match mode `SEQUENCE`, 4 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 1 | `signature_name`=C:\Windows\System32 accepted password<br>`hostname`=SEC-WKS-674<br>`agent_ip`=10.42.165.200<br>`severity_id`=3<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection RDP brute<br>`hostname`=SEC-WKS-674<br>`agent_ip`=10.42.165.200<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection RDP brute<br>`hostname`=SEC-WKS-674<br>`agent_ip`=10.42.165.200<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection RDP brute<br>`hostname`=SEC-WKS-674<br>`agent_ip`=10.42.165.200<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 4 of 4 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.165.200`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection RDP brute<br>`hostname`=SEC-WKS-674<br>`agent_ip`=10.42.165.200<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/3 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection RDP brute<br>`hostname`=SEC-WKS-674<br>`agent_ip`=10.42.165.200<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/3 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection RDP brute<br>`hostname`=SEC-WKS-674<br>`agent_ip`=10.42.165.200<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/3 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +3600s (rule window) |
| 4 | 2026-03-02T09:16:02.000Z | 1 | `signature_name`=C:\Windows\System32 accepted password<br>`hostname`=SEC-WKS-674<br>`agent_ip`=10.42.165.200<br>`severity_id`=3<br>… | arrives 960s after the previous stage completed, past the 600s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 4 of 4 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.165.200`

