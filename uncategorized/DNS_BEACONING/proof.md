# Proof — DNS_BEACONING

## Rule

- **Rule ID:** DNS_BEACONING
- **Rule name:** Repeated suspicious DNS queries (DGA / DNS tunnelling) from same host
- **Rule shape:** THRESHOLD
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [zeek, suricata]
- **Replay wire:** zeek on topic `replay-events-zeek`
- **Correlation key:** `entity_key`
- **Window:** 1200s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [] / []
- **Behavioral constraints:** declared on the rule

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 3.0
- Events required: 3

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains dns_suspicious | `Zeek::Notice Scan::Address_Scan dns_suspicious` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 3 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan dns_suspicious<br>`hostname`=SEC-WKS-149<br>`agent_ip`=10.42.140.114<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/3; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan dns_suspicious<br>`hostname`=SEC-WKS-149<br>`agent_ip`=10.42.140.114<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/3 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan dns_suspicious<br>`hostname`=SEC-WKS-149<br>`agent_ip`=10.42.140.114<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/3 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `zeek`, lane key = `10.42.140.114`
- alert `bf694c54b32e07a8cf523bd32a8e2b48` on lane `entity_key` = `10.42.140.114`, match mode `THRESHOLD`, 3 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 3 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 dns tunnel<br>`hostname`=OPS-WKS-148<br>`agent_ip`=10.42.139.114<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/3; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T10:00:01.000Z | 0 | `signature_name`=C:\Windows\System32 dns tunnel<br>`hostname`=OPS-WKS-148<br>`agent_ip`=10.42.139.114<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/3 |
| 3 | 2026-03-02T10:00:02.000Z | 0 | `signature_name`=C:\Windows\System32 dns tunnel<br>`hostname`=OPS-WKS-148<br>`agent_ip`=10.42.139.114<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/3 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `zeek`, lane key = `10.42.139.114`
- alert `11617540d53eeea69e578e7faf6e4a19` on lane `entity_key` = `10.42.139.114`, match mode `THRESHOLD`, 3 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** count reaches 2 of the required 3 — one event short of the threshold

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan dns_suspicious<br>`hostname`=SEC-WKS-149<br>`agent_ip`=10.42.140.114<br>`severity_id`=3<br>… | counts toward the aggregate but stops at 2, below the threshold of 3 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan dns_suspicious<br>`hostname`=SEC-WKS-149<br>`agent_ip`=10.42.140.114<br>`severity_id`=3<br>… | counts toward the aggregate but stops at 2, below the threshold of 3 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `zeek`, lane key = `10.42.140.114`

## benign_2

**Expected alerts:** 0  
**Construction:** the final event falls outside the 1200s window, so the anchored window restarts and the count never accumulates

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan dns_suspicious<br>`hostname`=SEC-WKS-149<br>`agent_ip`=10.42.140.114<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/3; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan dns_suspicious<br>`hostname`=SEC-WKS-149<br>`agent_ip`=10.42.140.114<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/3 |
| 3 | 2026-03-02T09:21:00.000Z | 0 | `signature_name`=Zeek::Notice Scan::Address_Scan dns_suspicious<br>`hostname`=SEC-WKS-149<br>`agent_ip`=10.42.140.114<br>`severity_id`=3<br>… | arrives 1260s after the window anchor (window is 1200s), so the evaluator resets the window and this event restarts the count at 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `zeek`, lane key = `10.42.140.114`

