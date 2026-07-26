# Proof — DNS_QUERY_RATE_SPIKE

## Rule

- **Rule ID:** DNS_QUERY_RATE_SPIKE
- **Rule name:** Abnormal DNS query volume from single host in 5 minutes — DGA C2 characteristic or DNS tunneling (T1568, T1071.004). Behavior-driven, no signature required.
- **Rule shape:** THRESHOLD
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [zeek, suricata]
- **Replay wire:** zeek on topic `replay-events-zeek`
- **Correlation key:** `entity_key`
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [TA0011, TA0010, TA0043] / []
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 20.0
- Events required: 20

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic in_list [TA0011, TA0010, TA0043] | `TA0011` |
| `signature_name` | signature_name contains dns_query | `Zeek::Notice Scan::Address_Scan dns_query` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 20 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/20; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/20 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/20 |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/20 |
| 5 | 2026-03-02T09:00:04.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/20 |
| 6 | 2026-03-02T09:00:05.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 6/20 |
| 7 | 2026-03-02T09:00:06.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 7/20 |
| 8 | 2026-03-02T09:00:07.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 8/20 |
| 9 | 2026-03-02T09:00:08.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 9/20 |
| 10 | 2026-03-02T09:00:09.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 10/20 |
| 11 | 2026-03-02T09:00:10.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 11/20 |
| 12 | 2026-03-02T09:00:11.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 12/20 |
| 13 | 2026-03-02T09:00:12.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 13/20 |
| 14 | 2026-03-02T09:00:13.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 14/20 |
| 15 | 2026-03-02T09:00:14.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 15/20 |
| 16 | 2026-03-02T09:00:15.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 16/20 |
| 17 | 2026-03-02T09:00:16.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 17/20 |
| 18 | 2026-03-02T09:00:17.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 18/20 |
| 19 | 2026-03-02T09:00:18.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 19/20 |
| 20 | 2026-03-02T09:00:19.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 20/20 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 20 of 20 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `zeek`, lane key = `10.42.34.82`
- alert `781a23e8537d9f7ae6f8174846a5f8e2` on lane `entity_key` = `10.42.34.82`, match mode `THRESHOLD`, 20 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 20 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/20; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T10:00:01.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/20 |
| 3 | 2026-03-02T10:00:02.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/20 |
| 4 | 2026-03-02T10:00:03.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/20 |
| 5 | 2026-03-02T10:00:04.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/20 |
| 6 | 2026-03-02T10:00:05.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 6/20 |
| 7 | 2026-03-02T10:00:06.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 7/20 |
| 8 | 2026-03-02T10:00:07.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 8/20 |
| 9 | 2026-03-02T10:00:08.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 9/20 |
| 10 | 2026-03-02T10:00:09.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 10/20 |
| 11 | 2026-03-02T10:00:10.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 11/20 |
| 12 | 2026-03-02T10:00:11.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 12/20 |
| 13 | 2026-03-02T10:00:12.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 13/20 |
| 14 | 2026-03-02T10:00:13.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 14/20 |
| 15 | 2026-03-02T10:00:14.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 15/20 |
| 16 | 2026-03-02T10:00:15.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 16/20 |
| 17 | 2026-03-02T10:00:16.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 17/20 |
| 18 | 2026-03-02T10:00:17.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 18/20 |
| 19 | 2026-03-02T10:00:18.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 19/20 |
| 20 | 2026-03-02T10:00:19.000Z | 0 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 DNS query<br>`hostname`=SEC-WKS-044<br>`agent_ip`=10.42.35.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 20/20 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 20 of 20 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `zeek`, lane key = `10.42.35.82`
- alert `2710dddf1b06114cec6def09f7183883` on lane `entity_key` = `10.42.35.82`, match mode `THRESHOLD`, 20 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** count reaches 19 of the required 20 — one event short of the threshold

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 5 | 2026-03-02T09:00:04.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 6 | 2026-03-02T09:00:05.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 7 | 2026-03-02T09:00:06.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 8 | 2026-03-02T09:00:07.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 9 | 2026-03-02T09:00:08.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 10 | 2026-03-02T09:00:09.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 11 | 2026-03-02T09:00:10.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 12 | 2026-03-02T09:00:11.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 13 | 2026-03-02T09:00:12.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 14 | 2026-03-02T09:00:13.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 15 | 2026-03-02T09:00:14.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 16 | 2026-03-02T09:00:15.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 17 | 2026-03-02T09:00:16.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 18 | 2026-03-02T09:00:17.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |
| 19 | 2026-03-02T09:00:18.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | counts toward the aggregate but stops at 19, below the threshold of 20 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 19 of 19 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `zeek`, lane key = `10.42.34.82`

## benign_2

**Expected alerts:** 0  
**Construction:** the final event falls outside the 300s window, so the anchored window restarts and the count never accumulates

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/20; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/20 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/20 |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/20 |
| 5 | 2026-03-02T09:00:04.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/20 |
| 6 | 2026-03-02T09:00:05.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 6/20 |
| 7 | 2026-03-02T09:00:06.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 7/20 |
| 8 | 2026-03-02T09:00:07.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 8/20 |
| 9 | 2026-03-02T09:00:08.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 9/20 |
| 10 | 2026-03-02T09:00:09.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 10/20 |
| 11 | 2026-03-02T09:00:10.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 11/20 |
| 12 | 2026-03-02T09:00:11.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 12/20 |
| 13 | 2026-03-02T09:00:12.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 13/20 |
| 14 | 2026-03-02T09:00:13.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 14/20 |
| 15 | 2026-03-02T09:00:14.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 15/20 |
| 16 | 2026-03-02T09:00:15.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 16/20 |
| 17 | 2026-03-02T09:00:16.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 17/20 |
| 18 | 2026-03-02T09:00:17.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 18/20 |
| 19 | 2026-03-02T09:00:18.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 19/20 |
| 20 | 2026-03-02T09:06:00.000Z | 0 | `tactic`=TA0011<br>`signature_name`=Zeek::Notice Scan::Address_Scan dns_query<br>`hostname`=OPS-WKS-043<br>`agent_ip`=10.42.34.82<br>… | arrives 360s after the window anchor (window is 300s), so the evaluator resets the window and this event restarts the count at 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-zeek` and `MultiLaneRuleEvaluator`:

- events ingested: 20 of 20 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `zeek`, lane key = `10.42.34.82`

