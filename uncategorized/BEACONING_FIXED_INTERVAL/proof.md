# Proof — BEACONING_FIXED_INTERVAL

## Rule

- **Rule ID:** BEACONING_FIXED_INTERVAL
- **Rule name:** Single host making 5+ outbound C2-tactic connections in 60 minutes — frequency-based beacon detection with no signature dependency; catches custom implants, encrypted C2, novel frameworks (T1071, T1095, T1573)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [zeek, suricata]
- **Replay wire:** zeek on topic `replay-events-zeek`
- **Correlation key:** `entity_key`
- **Window:** 3600s, min span 120s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [TA0011] / []
- **Behavioral constraints:** declared on the rule

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 5.0
- Events required: 5

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name not_contains bittorrent AND signature_name not_contains vuze AND signature_name not_contains dht AND signature_name not_contains torrent AND signature_name not_contains USER_AGENTS AND signature_name not_contains suspicious user agent AND signature_name not_contains suspicious UA AND signature_name not_contains User-Agent | `Zeek::Notice Scan::Address_Scan` |
| `tactic` | tactic in_list [TA0011] | `TA0011` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 5 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=ENG-WKS-132<br>`agent_ip`=10.42.23.123<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/5; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:00:30.250Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=ENG-WKS-132<br>`agent_ip`=10.42.23.123<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/5 |
| 3 | 2026-03-02T09:01:00.500Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=ENG-WKS-132<br>`agent_ip`=10.42.23.123<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/5 |
| 4 | 2026-03-02T09:01:30.750Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=ENG-WKS-132<br>`agent_ip`=10.42.23.123<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/5 |
| 5 | 2026-03-02T09:02:01.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=ENG-WKS-132<br>`agent_ip`=10.42.23.123<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/5 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 5 of 5 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `zeek`, lane key = `10.42.23.123`
- alert `066fbc1d0984cff62ab62137adbf76bd` on lane `entity_key` = `10.42.23.123`, match mode `THRESHOLD`, 5 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 5 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=OPS-WKS-133<br>`agent_ip`=10.42.24.123<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/5; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T10:00:30.250Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=OPS-WKS-133<br>`agent_ip`=10.42.24.123<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/5 |
| 3 | 2026-03-02T10:01:00.500Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=OPS-WKS-133<br>`agent_ip`=10.42.24.123<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/5 |
| 4 | 2026-03-02T10:01:30.750Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=OPS-WKS-133<br>`agent_ip`=10.42.24.123<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/5 |
| 5 | 2026-03-02T10:02:01.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=OPS-WKS-133<br>`agent_ip`=10.42.24.123<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/5 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 5 of 5 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `zeek`, lane key = `10.42.24.123`
- alert `224e3cf52a1df97d2122f11e054db2f3` on lane `entity_key` = `10.42.24.123`, match mode `THRESHOLD`, 5 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** count reaches 4 of the required 5 — one event short of the threshold

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=ENG-WKS-132<br>`agent_ip`=10.42.23.123<br>… | counts toward the aggregate but stops at 4, below the threshold of 5 |
| 2 | 2026-03-02T09:00:30.250Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=ENG-WKS-132<br>`agent_ip`=10.42.23.123<br>… | counts toward the aggregate but stops at 4, below the threshold of 5 |
| 3 | 2026-03-02T09:01:00.500Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=ENG-WKS-132<br>`agent_ip`=10.42.23.123<br>… | counts toward the aggregate but stops at 4, below the threshold of 5 |
| 4 | 2026-03-02T09:01:30.750Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=ENG-WKS-132<br>`agent_ip`=10.42.23.123<br>… | counts toward the aggregate but stops at 4, below the threshold of 5 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 4 of 4 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `zeek`, lane key = `10.42.23.123`

## benign_2

**Expected alerts:** 0  
**Construction:** the final event falls outside the 3600s window, so the anchored window restarts and the count never accumulates

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=ENG-WKS-132<br>`agent_ip`=10.42.23.123<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/5; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:00:30.250Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=ENG-WKS-132<br>`agent_ip`=10.42.23.123<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/5 |
| 3 | 2026-03-02T09:01:00.500Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=ENG-WKS-132<br>`agent_ip`=10.42.23.123<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/5 |
| 4 | 2026-03-02T09:01:30.750Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=ENG-WKS-132<br>`agent_ip`=10.42.23.123<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/5 |
| 5 | 2026-03-02T10:01:00.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan<br>`tactic`=TA0011<br>`hostname`=ENG-WKS-132<br>`agent_ip`=10.42.23.123<br>… | arrives 3660s after the window anchor (window is 3600s), so the evaluator resets the window and this event restarts the count at 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 5 of 5 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `zeek`, lane key = `10.42.23.123`

