# Proof — 11111111-0000-0000-0000-000000000001

## Rule

- **Rule ID:** 11111111-0000-0000-0000-000000000001
- **Rule name:** Repeated hostile or IOC DNS/outbound from one host
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [suricata]
- **Replay wire:** suricata on topic `replay-events-nids`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 600s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [command-and-control] / [T1071.004]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 3.0
- `within_seconds` = 600 (deadline for the next stage)
- Stage correlation key: `src_ip`
- Events required: 3

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains Likely Hostile | `ET MALWARE Observed Suspicious Outbound Connection Likely Hostile` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 3 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection Likely…<br>`hostname`=ENG-WKS-332<br>`agent_ip`=10.42.23.37<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/3 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection Likely…<br>`hostname`=ENG-WKS-332<br>`agent_ip`=10.42.23.37<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/3 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection Likely…<br>`hostname`=ENG-WKS-332<br>`agent_ip`=10.42.23.37<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/3 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.23.37`
- alert `888a59f077c33b84506170f06af4f2fb` on lane `entity_key` = `10.42.23.37`, match mode `THRESHOLD`, 3 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 3 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 IOC Suspicious IP Communication<br>`hostname`=OPS-WKS-333<br>`agent_ip`=10.42.24.37<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/3 |
| 2 | 2026-03-02T10:00:01.000Z | 0 | `signature_name`=C:\Windows\System32 IOC Suspicious IP Communication<br>`hostname`=OPS-WKS-333<br>`agent_ip`=10.42.24.37<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/3 |
| 3 | 2026-03-02T10:00:02.000Z | 0 | `signature_name`=C:\Windows\System32 IOC Suspicious IP Communication<br>`hostname`=OPS-WKS-333<br>`agent_ip`=10.42.24.37<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/3 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.24.37`
- alert `98fef3250e781184b3dd09a61127ad0e` on lane `entity_key` = `10.42.24.37`, match mode `THRESHOLD`, 3 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** count reaches 2 of the required 3 — one event short of the threshold

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection Likely…<br>`hostname`=ENG-WKS-332<br>`agent_ip`=10.42.23.37<br>`severity_id`=3<br>… | counts toward the aggregate but stops at 2, below the threshold of 3 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection Likely…<br>`hostname`=ENG-WKS-332<br>`agent_ip`=10.42.23.37<br>`severity_id`=3<br>… | counts toward the aggregate but stops at 2, below the threshold of 3 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 2 of 2 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.23.37`

## benign_2

**Expected alerts:** 0  
**Construction:** the final event falls outside the 600s window, so the anchored window restarts and the count never accumulates

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection Likely…<br>`hostname`=ENG-WKS-332<br>`agent_ip`=10.42.23.37<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/3 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection Likely…<br>`hostname`=ENG-WKS-332<br>`agent_ip`=10.42.23.37<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/3 |
| 3 | 2026-03-02T09:11:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection Likely…<br>`hostname`=ENG-WKS-332<br>`agent_ip`=10.42.23.37<br>`severity_id`=3<br>… | arrives 660s after the window anchor (window is 600s), so the evaluator resets the window and this event restarts the count at 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 3 of 3 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.23.37`

