# Proof — SLOW_CREDENTIAL_STUFFING

## Rule

- **Rule ID:** SLOW_CREDENTIAL_STUFFING
- **Rule name:** Low-and-slow credential stuffing: many login failures → eventual success over 24h
- **Rule shape:** SEQUENCE
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [wazuh]
- **Replay wire:** wazuh on topic `replay-events-hids`
- **Correlation key:** `entity_key`
- **Window:** 86400s
- **Max gap:** _(not set)_
- **Stages:** 2
- **MITRE:** [] / []
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 5.0
- Events required: 5

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains failed login | `Windows audit failure event failed login` |

### Stage 1

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains logon success | `C:\Windows\System32 logon success` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 5 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=Windows audit failure event failed login<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/5 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=Windows audit failure event failed login<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/5 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `signature_name`=Windows audit failure event failed login<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/5 |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `signature_name`=Windows audit failure event failed login<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/5 |
| 5 | 2026-03-02T09:00:04.000Z | 0 | `signature_name`=Windows audit failure event failed login<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/5 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +86400s (rule window) |
| 6 | 2026-03-02T09:05:04.000Z | 1 | `signature_name`=C:\Windows\System32 logon success<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 6 of 6 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `wazuh`, lane key = `10.42.116.27`
- alert `a8df8ec04794483e57607b20abcc2a60` on lane `entity_key` = `10.42.116.27`, match mode `SEQUENCE`, 6 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 5 event(s) → stage 1 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 authentication failure<br>`hostname`=SEC-WKS-724<br>`agent_ip`=10.42.115.27<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/5 |
| 2 | 2026-03-02T10:00:01.000Z | 0 | `signature_name`=C:\Windows\System32 authentication failure<br>`hostname`=SEC-WKS-724<br>`agent_ip`=10.42.115.27<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/5 |
| 3 | 2026-03-02T10:00:02.000Z | 0 | `signature_name`=C:\Windows\System32 authentication failure<br>`hostname`=SEC-WKS-724<br>`agent_ip`=10.42.115.27<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/5 |
| 4 | 2026-03-02T10:00:03.000Z | 0 | `signature_name`=C:\Windows\System32 authentication failure<br>`hostname`=SEC-WKS-724<br>`agent_ip`=10.42.115.27<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/5 |
| 5 | 2026-03-02T10:00:04.000Z | 0 | `signature_name`=C:\Windows\System32 authentication failure<br>`hostname`=SEC-WKS-724<br>`agent_ip`=10.42.115.27<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/5 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +86400s (rule window) |
| 6 | 2026-03-02T10:05:04.000Z | 1 | `signature_name`=C:\Users\j.mercer\AppData\Local\Temp 4624<br>`hostname`=SEC-WKS-724<br>`agent_ip`=10.42.115.27<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 6 of 6 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `wazuh`, lane key = `10.42.115.27`
- alert `aa08c515ee67f413117c26616e14536f` on lane `entity_key` = `10.42.115.27`, match mode `SEQUENCE`, 6 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 1 | `signature_name`=C:\Windows\System32 logon success<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=Windows audit failure event failed login<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `signature_name`=Windows audit failure event failed login<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `signature_name`=Windows audit failure event failed login<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 5 | 2026-03-02T09:00:04.000Z | 0 | `signature_name`=Windows audit failure event failed login<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |
| 6 | 2026-03-02T09:00:05.000Z | 0 | `signature_name`=Windows audit failure event failed login<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | completes stage 0, but the stage-1 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 6 of 6 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `wazuh`, lane key = `10.42.116.27`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=Windows audit failure event failed login<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/5 |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=Windows audit failure event failed login<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 2/5 |
| 3 | 2026-03-02T09:00:02.000Z | 0 | `signature_name`=Windows audit failure event failed login<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 3/5 |
| 4 | 2026-03-02T09:00:03.000Z | 0 | `signature_name`=Windows audit failure event failed login<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 4/5 |
| 5 | 2026-03-02T09:00:04.000Z | 0 | `signature_name`=Windows audit failure event failed login<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 5/5 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +86400s (rule window) |
| 6 | 2026-03-02T09:16:04.000Z | 1 | `signature_name`=C:\Windows\System32 logon success<br>`hostname`=FIN-WKS-725<br>`agent_ip`=10.42.116.27<br>`severity_id`=3<br>… | arrives 960s after the previous stage completed, past the 600s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-hids` and `MultiLaneRuleEvaluator`:

- events ingested: 6 of 6 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `wazuh`, lane key = `10.42.116.27`

