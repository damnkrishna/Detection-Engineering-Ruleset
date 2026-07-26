# Proof — WANNACRY_REPEATED_DNS

## Rule

- **Rule ID:** WANNACRY_REPEATED_DNS
- **Rule name:** Repeated WannaCry kill-switch DNS lookups — active ransomware infection confirmed
- **Rule shape:** THRESHOLD
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [suricata]
- **Replay wire:** suricata on topic `replay-events-nids`
- **Correlation key:** `entity_key`
- **Window:** 1800s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [TA0011] / [T1071.004]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 2.0
- Events required: 2

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains wannacry | `ET MALWARE Observed Suspicious Outbound Connection wannacry` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 2 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection wannacry<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.196.138<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/2; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection wannacry<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.196.138<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/2 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.196.138`
- alert `b96c5618ee0e767bb7c4242ae64ba13d` on lane `entity_key` = `10.42.196.138`, match mode `THRESHOLD`, 2 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 2 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 iuqerfsodp9<br>`hostname`=SEC-WKS-104<br>`agent_ip`=10.42.195.138<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/2; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T10:00:01.000Z | 0 | `signature_name`=C:\Windows\System32 iuqerfsodp9<br>`hostname`=SEC-WKS-104<br>`agent_ip`=10.42.195.138<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/2 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.195.138`
- alert `f5150c1698ca8bb51e08aff9f74a2ca6` on lane `entity_key` = `10.42.195.138`, match mode `THRESHOLD`, 2 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** count reaches 1 of the required 2 — one event short of the threshold

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection wannacry<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.196.138<br>`severity_id`=3<br>… | counts toward the aggregate but stops at 1, below the threshold of 2 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.196.138`

## benign_2

**Expected alerts:** 0  
**Construction:** the final event falls outside the 1800s window, so the anchored window restarts and the count never accumulates

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection wannacry<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.196.138<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/2; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:31:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection wannacry<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.196.138<br>`severity_id`=3<br>… | arrives 1860s after the window anchor (window is 1800s), so the evaluator resets the window and this event restarts the count at 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.196.138`

