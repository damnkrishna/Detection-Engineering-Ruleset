# Proof — DNS_NXDOMAIN_RATIO_ANOMALY

## Rule

- **Rule ID:** DNS_NXDOMAIN_RATIO_ANOMALY
- **Rule name:** ≥15 NXDOMAIN responses from single host in 5 minutes — DGA C2 lookup pattern, behavior-driven, no signature dependency (T1568.002)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [zeek, suricata]
- **Replay wire:** zeek on topic `replay-events-zeek`
- **Correlation key:** `entity_key`
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [TA0011, TA0043] / [T1568.002]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 15.0
- Events required: 15

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic in_list [TA0011, TA0043] | `TA0011` |
| `signature_name` | signature_name contains NXDOMAIN | `Zeek::Notice Scan::Address_Scan NXDOMAIN` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 15 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/15; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/15 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/15 |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/15 |
| 5 | 2026-03-02T09:00:04.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/15 |
| 6 | 2026-03-02T09:00:05.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 6/15 |
| 7 | 2026-03-02T09:00:06.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 7/15 |
| 8 | 2026-03-02T09:00:07.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 8/15 |
| 9 | 2026-03-02T09:00:08.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 9/15 |
| 10 | 2026-03-02T09:00:09.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 10/15 |
| 11 | 2026-03-02T09:00:10.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 11/15 |
| 12 | 2026-03-02T09:00:11.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 12/15 |
| 13 | 2026-03-02T09:00:12.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 13/15 |
| 14 | 2026-03-02T09:00:13.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 14/15 |
| 15 | 2026-03-02T09:00:14.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 15/15 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 15 of 15 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `zeek`, lane key = `10.42.80.184`
- alert `0dcb794a6c278101a31a43096175a37e` on lane `entity_key` = `10.42.80.184`, match mode `THRESHOLD`, 15 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 15 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `tactic`=TA0043<br>`signature_name`=C:\Windows\System32 non-existent domain<br>`hostname`=OPS-WKS-488<br>`agent_ip`=10.42.79.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/15; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T10:00:01.000Z | 0 | `tactic`=TA0043<br>`signature_name`=C:\Windows\System32 non-existent domain<br>`hostname`=OPS-WKS-488<br>`agent_ip`=10.42.79.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/15 |
| 3 | 2026-03-02T10:00:02.000Z | 0 | `tactic`=TA0043<br>`signature_name`=C:\Windows\System32 non-existent domain<br>`hostname`=OPS-WKS-488<br>`agent_ip`=10.42.79.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/15 |
| 4 | 2026-03-02T10:00:03.000Z | 0 | `tactic`=TA0043<br>`signature_name`=C:\Windows\System32 non-existent domain<br>`hostname`=OPS-WKS-488<br>`agent_ip`=10.42.79.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/15 |
| 5 | 2026-03-02T10:00:04.000Z | 0 | `tactic`=TA0043<br>`signature_name`=C:\Windows\System32 non-existent domain<br>`hostname`=OPS-WKS-488<br>`agent_ip`=10.42.79.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/15 |
| 6 | 2026-03-02T10:00:05.000Z | 0 | `tactic`=TA0043<br>`signature_name`=C:\Windows\System32 non-existent domain<br>`hostname`=OPS-WKS-488<br>`agent_ip`=10.42.79.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 6/15 |
| 7 | 2026-03-02T10:00:06.000Z | 0 | `tactic`=TA0043<br>`signature_name`=C:\Windows\System32 non-existent domain<br>`hostname`=OPS-WKS-488<br>`agent_ip`=10.42.79.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 7/15 |
| 8 | 2026-03-02T10:00:07.000Z | 0 | `tactic`=TA0043<br>`signature_name`=C:\Windows\System32 non-existent domain<br>`hostname`=OPS-WKS-488<br>`agent_ip`=10.42.79.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 8/15 |
| 9 | 2026-03-02T10:00:08.000Z | 0 | `tactic`=TA0043<br>`signature_name`=C:\Windows\System32 non-existent domain<br>`hostname`=OPS-WKS-488<br>`agent_ip`=10.42.79.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 9/15 |
| 10 | 2026-03-02T10:00:09.000Z | 0 | `tactic`=TA0043<br>`signature_name`=C:\Windows\System32 non-existent domain<br>`hostname`=OPS-WKS-488<br>`agent_ip`=10.42.79.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 10/15 |
| 11 | 2026-03-02T10:00:10.000Z | 0 | `tactic`=TA0043<br>`signature_name`=C:\Windows\System32 non-existent domain<br>`hostname`=OPS-WKS-488<br>`agent_ip`=10.42.79.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 11/15 |
| 12 | 2026-03-02T10:00:11.000Z | 0 | `tactic`=TA0043<br>`signature_name`=C:\Windows\System32 non-existent domain<br>`hostname`=OPS-WKS-488<br>`agent_ip`=10.42.79.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 12/15 |
| 13 | 2026-03-02T10:00:12.000Z | 0 | `tactic`=TA0043<br>`signature_name`=C:\Windows\System32 non-existent domain<br>`hostname`=OPS-WKS-488<br>`agent_ip`=10.42.79.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 13/15 |
| 14 | 2026-03-02T10:00:13.000Z | 0 | `tactic`=TA0043<br>`signature_name`=C:\Windows\System32 non-existent domain<br>`hostname`=OPS-WKS-488<br>`agent_ip`=10.42.79.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 14/15 |
| 15 | 2026-03-02T10:00:14.000Z | 0 | `tactic`=TA0043<br>`signature_name`=C:\Windows\System32 non-existent domain<br>`hostname`=OPS-WKS-488<br>`agent_ip`=10.42.79.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 15/15 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 15 of 15 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `zeek`, lane key = `10.42.79.184`
- alert `107c7e2e1f935b8e759af9d403d70b2e` on lane `entity_key` = `10.42.79.184`, match mode `THRESHOLD`, 15 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** count reaches 14 of the required 15 — one event short of the threshold

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | counts toward the aggregate but stops at 14, below the threshold of 15 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | counts toward the aggregate but stops at 14, below the threshold of 15 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | counts toward the aggregate but stops at 14, below the threshold of 15 |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | counts toward the aggregate but stops at 14, below the threshold of 15 |
| 5 | 2026-03-02T09:00:04.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | counts toward the aggregate but stops at 14, below the threshold of 15 |
| 6 | 2026-03-02T09:00:05.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | counts toward the aggregate but stops at 14, below the threshold of 15 |
| 7 | 2026-03-02T09:00:06.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | counts toward the aggregate but stops at 14, below the threshold of 15 |
| 8 | 2026-03-02T09:00:07.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | counts toward the aggregate but stops at 14, below the threshold of 15 |
| 9 | 2026-03-02T09:00:08.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | counts toward the aggregate but stops at 14, below the threshold of 15 |
| 10 | 2026-03-02T09:00:09.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | counts toward the aggregate but stops at 14, below the threshold of 15 |
| 11 | 2026-03-02T09:00:10.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | counts toward the aggregate but stops at 14, below the threshold of 15 |
| 12 | 2026-03-02T09:00:11.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | counts toward the aggregate but stops at 14, below the threshold of 15 |
| 13 | 2026-03-02T09:00:12.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | counts toward the aggregate but stops at 14, below the threshold of 15 |
| 14 | 2026-03-02T09:00:13.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | counts toward the aggregate but stops at 14, below the threshold of 15 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 14 of 14 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `zeek`, lane key = `10.42.80.184`

## benign_2

**Expected alerts:** 0  
**Construction:** the final event falls outside the 300s window, so the anchored window restarts and the count never accumulates

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/15; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/15 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/15 |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/15 |
| 5 | 2026-03-02T09:00:04.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/15 |
| 6 | 2026-03-02T09:00:05.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 6/15 |
| 7 | 2026-03-02T09:00:06.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 7/15 |
| 8 | 2026-03-02T09:00:07.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 8/15 |
| 9 | 2026-03-02T09:00:08.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 9/15 |
| 10 | 2026-03-02T09:00:09.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 10/15 |
| 11 | 2026-03-02T09:00:10.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 11/15 |
| 12 | 2026-03-02T09:00:11.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 12/15 |
| 13 | 2026-03-02T09:00:12.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 13/15 |
| 14 | 2026-03-02T09:00:13.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | satisfies every condition of stage 0; increments the count aggregate to 14/15 |
| 15 | 2026-03-02T09:06:00.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan NXDOMAIN<br>`hostname`=SEC-WKS-489<br>`agent_ip`=10.42.80.184<br>… | arrives 360s after the window anchor (window is 300s), so the evaluator resets the window and this event restarts the count at 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 15 of 15 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `zeek`, lane key = `10.42.80.184`

