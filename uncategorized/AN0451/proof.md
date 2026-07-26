# Proof — AN0451

## Rule

- **Rule ID:** AN0451
- **Rule name:** Potential MFA Fatigue Attack (AN0451)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon, auth]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 600s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [credential-access] / [T1621]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 5.0
- `within_seconds` = 600 (deadline for the next stage)
- Events required: 5

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `action` | action in_list [mfa_denied, mfa_ignored, mfa_timeout, push_sent] | `mfa_denied` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 5 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `action`=mfa_denied<br>`hostname`=FIN-WKS-060<br>`agent_ip`=10.42.151.136<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/5 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `action`=mfa_denied<br>`hostname`=FIN-WKS-060<br>`agent_ip`=10.42.151.136<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/5 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `action`=mfa_denied<br>`hostname`=FIN-WKS-060<br>`agent_ip`=10.42.151.136<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/5 |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `action`=mfa_denied<br>`hostname`=FIN-WKS-060<br>`agent_ip`=10.42.151.136<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/5 |
| 5 | 2026-03-02T09:00:04.000Z | 0 | `action`=mfa_denied<br>`hostname`=FIN-WKS-060<br>`agent_ip`=10.42.151.136<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/5 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 5 of 5 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.151.136`
- alert `c5bc7d82b94c8b3cbb1e3133f15b6c73` on lane `entity_key` = `10.42.151.136`, match mode `THRESHOLD`, 5 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 5 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `action`=mfa_ignored<br>`hostname`=SEC-WKS-059<br>`agent_ip`=10.42.150.136<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/5 |
| 2 | 2026-03-02T10:00:01.000Z | 0 | `action`=mfa_ignored<br>`hostname`=SEC-WKS-059<br>`agent_ip`=10.42.150.136<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/5 |
| 3 | 2026-03-02T10:00:02.000Z | 0 | `action`=mfa_ignored<br>`hostname`=SEC-WKS-059<br>`agent_ip`=10.42.150.136<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/5 |
| 4 | 2026-03-02T10:00:03.000Z | 0 | `action`=mfa_ignored<br>`hostname`=SEC-WKS-059<br>`agent_ip`=10.42.150.136<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/5 |
| 5 | 2026-03-02T10:00:04.000Z | 0 | `action`=mfa_ignored<br>`hostname`=SEC-WKS-059<br>`agent_ip`=10.42.150.136<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/5 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 5 of 5 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.150.136`
- alert `82ec3ca81b221bb5937552ccf1d1ff62` on lane `entity_key` = `10.42.150.136`, match mode `THRESHOLD`, 5 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** count reaches 4 of the required 5 — one event short of the threshold

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `action`=mfa_denied<br>`hostname`=FIN-WKS-060<br>`agent_ip`=10.42.151.136<br>`event_id`=1<br>… | counts toward the aggregate but stops at 4, below the threshold of 5 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `action`=mfa_denied<br>`hostname`=FIN-WKS-060<br>`agent_ip`=10.42.151.136<br>`event_id`=1<br>… | counts toward the aggregate but stops at 4, below the threshold of 5 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `action`=mfa_denied<br>`hostname`=FIN-WKS-060<br>`agent_ip`=10.42.151.136<br>`event_id`=1<br>… | counts toward the aggregate but stops at 4, below the threshold of 5 |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `action`=mfa_denied<br>`hostname`=FIN-WKS-060<br>`agent_ip`=10.42.151.136<br>`event_id`=1<br>… | counts toward the aggregate but stops at 4, below the threshold of 5 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 4 of 4 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.151.136`

## benign_2

**Expected alerts:** 0  
**Construction:** the final event falls outside the 600s window, so the anchored window restarts and the count never accumulates

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `action`=mfa_denied<br>`hostname`=FIN-WKS-060<br>`agent_ip`=10.42.151.136<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/5 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `action`=mfa_denied<br>`hostname`=FIN-WKS-060<br>`agent_ip`=10.42.151.136<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/5 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `action`=mfa_denied<br>`hostname`=FIN-WKS-060<br>`agent_ip`=10.42.151.136<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/5 |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `action`=mfa_denied<br>`hostname`=FIN-WKS-060<br>`agent_ip`=10.42.151.136<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/5 |
| 5 | 2026-03-02T09:11:00.000Z | 0 | `action`=mfa_denied<br>`hostname`=FIN-WKS-060<br>`agent_ip`=10.42.151.136<br>`event_id`=1<br>… | arrives 660s after the window anchor (window is 600s), so the evaluator resets the window and this event restarts the count at 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 5 of 5 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.151.136`

