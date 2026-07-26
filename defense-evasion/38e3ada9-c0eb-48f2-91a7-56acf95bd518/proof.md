# Proof — 38e3ada9-c0eb-48f2-91a7-56acf95bd518

## Rule

- **Rule ID:** 38e3ada9-c0eb-48f2-91a7-56acf95bd518
- **Rule name:** Execution of DLL with Suspicious or Revoked Code Signature (AN0643-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [defense-evasion] / [T1553.002]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_signature_status` | image_signature_status in_list [invalid, revoked, expired] | `invalid` |
| `image_loaded` | image_loaded contains \AppData\Local\Temp\ | `C:\Windows\System32\AppData\Local\Temp\` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_signature_status`=invalid<br>`image_loaded`=C:\Windows\System32\AppData\Local\Temp\<br>`hostname`=OPS-WKS-448<br>`agent_ip`=10.42.39.123<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.39.123`
- alert `de63656f31f552c92dcef9f6171f802b` on lane `entity_key` = `10.42.39.123`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `image_signature_status`=revoked<br>`image_loaded`=C:\Windows\System32\amsi.dll\Users\Public\<br>`hostname`=SEC-WKS-449<br>`agent_ip`=10.42.40.123<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.40.123`
- alert `0d47ceef2e0586b9d7b0808564a20ddc` on lane `entity_key` = `10.42.40.123`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_loaded contains \AppData\Local\Temp\' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_signature_status`=invalid<br>`image_loaded`=C:\Windows\System32\amsi.dll<br>`hostname`=OPS-WKS-448<br>`agent_ip`=10.42.39.123<br>… | image_loaded=C:\Windows\System32\amsi.dll fails 'image_loaded contains \AppData\Local\Temp\' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.39.123`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_signature_status in_list [invalid, revoked, expired]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_signature_status`=invalid.bak<br>`image_loaded`=C:\Windows\System32\AppData\Local\Temp\<br>`hostname`=OPS-WKS-448<br>`agent_ip`=10.42.39.123<br>… | image_signature_status=invalid.bak fails 'image_signature_status in_list [invalid, revoked, expired]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.39.123`

