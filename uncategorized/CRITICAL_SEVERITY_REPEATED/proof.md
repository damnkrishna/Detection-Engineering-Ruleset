# Proof — CRITICAL_SEVERITY_REPEATED

## Rule

- **Rule ID:** CRITICAL_SEVERITY_REPEATED
- **Rule name:** 3+ high/critical-severity alerts against same entity in 30 min — sustained active attack
- **Rule shape:** THRESHOLD
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [suricata]
- **Replay wire:** suricata on topic `replay-events-nids`
- **Correlation key:** `entity_key`
- **Window:** 1800s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [TA0001, TA0002, TA0004, TA0006, TA0008, TA0010, TA0011, TA0040] / []
- **Behavioral constraints:** declared on the rule

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 3.0
- Events required: 3

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name not_contains bittorrent AND signature_name not_contains vuze AND signature_name not_contains dht AND signature_name not_contains torrent | `ET MALWARE Observed Suspicious Outbound Connection` |
| `tactic` | tactic in_list [TA0001, TA0002, TA0004, TA0006, TA0008, TA0010, TA0011, TA0040] | `TA0001` |
| `severity_id` | severity_id in_list [4, 5] | `4` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 3 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection<br>`tactic`=TA0001<br>`severity_id`=4<br>`hostname`=FIN-WKS-245<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/3; carries logon type 3 (network) — the remote-auth evidence this rule is gated on; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection<br>`tactic`=TA0001<br>`severity_id`=4<br>`hostname`=FIN-WKS-245<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/3 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection<br>`tactic`=TA0001<br>`severity_id`=4<br>`hostname`=FIN-WKS-245<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/3 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.136.120`
- alert `46623a33c83fc678bbf50dc9cee9fbe3` on lane `entity_key` = `10.42.136.120`, match mode `THRESHOLD`, 3 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 3 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection<br>`tactic`=TA0002<br>`severity_id`=5<br>`hostname`=SEC-WKS-244<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/3; carries logon type 3 (network) — the remote-auth evidence this rule is gated on; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T10:00:01.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection<br>`tactic`=TA0002<br>`severity_id`=5<br>`hostname`=SEC-WKS-244<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/3 |
| 3 | 2026-03-02T10:00:02.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection<br>`tactic`=TA0002<br>`severity_id`=5<br>`hostname`=SEC-WKS-244<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/3 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.135.120`
- alert `694dc67775f7f3fdc289420b1b6d48d7` on lane `entity_key` = `10.42.135.120`, match mode `THRESHOLD`, 3 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** count reaches 2 of the required 3 — one event short of the threshold

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection<br>`tactic`=TA0001<br>`severity_id`=4<br>`hostname`=FIN-WKS-245<br>… | counts toward the aggregate but stops at 2, below the threshold of 3 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection<br>`tactic`=TA0001<br>`severity_id`=4<br>`hostname`=FIN-WKS-245<br>… | counts toward the aggregate but stops at 2, below the threshold of 3 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.136.120`

## benign_2

**Expected alerts:** 0  
**Construction:** the final event falls outside the 1800s window, so the anchored window restarts and the count never accumulates

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection<br>`tactic`=TA0001<br>`severity_id`=4<br>`hostname`=FIN-WKS-245<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/3; carries logon type 3 (network) — the remote-auth evidence this rule is gated on; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection<br>`tactic`=TA0001<br>`severity_id`=4<br>`hostname`=FIN-WKS-245<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/3 |
| 3 | 2026-03-02T09:31:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection<br>`tactic`=TA0001<br>`severity_id`=4<br>`hostname`=FIN-WKS-245<br>… | arrives 1860s after the window anchor (window is 1800s), so the evaluator resets the window and this event restarts the count at 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.136.120`

