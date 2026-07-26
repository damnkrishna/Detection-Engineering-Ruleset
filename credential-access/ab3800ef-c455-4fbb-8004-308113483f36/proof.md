# Proof — ab3800ef-c455-4fbb-8004-308113483f36

## Rule

- **Rule ID:** ab3800ef-c455-4fbb-8004-308113483f36
- **Rule name:** Suspicious AD FS Database Query for SAML Certificate Extraction via PowerShell Script Block (AN0420-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [credential-access, defense-evasion] / [T1606.002]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `script_block_text` | script_block_text contains Export-AdfsCertificate | `Get-Process \| Select-Object Name, Id Export-AdfsCertificate` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `script_block_text`=Get-Process \| Select-Object Name, Id Export-AdfsCertificate<br>`hostname`=FIN-WKS-605<br>`agent_ip`=10.42.196.43<br>`event_id`=4104<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.196.43`
- alert `f9f4678115100acd58973438488bb1cb` on lane `entity_key` = `10.42.196.43`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `script_block_text`=C:\Windows\System32 ADFSpoof<br>`hostname`=HR-WKS-606<br>`agent_ip`=10.42.197.43<br>`event_id`=4104<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.197.43`
- alert `297c8746d4f01b8ba0ea7cdc8611fc8f` on lane `entity_key` = `10.42.197.43`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'script_block_text contains Export-AdfsCertificate' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `script_block_text`=Get-Process \| Select-Object Name, Id<br>`hostname`=FIN-WKS-605<br>`agent_ip`=10.42.196.43<br>`event_id`=4104<br>… | script_block_text=Get-Process \| Select-Object Name, Id fails 'script_block_text contains Export-AdfsCertificate' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.196.43`

## benign_2

**Expected alerts:** 0  
**Construction:** the field 'script_block_text' is absent entirely; an absent field is no-match for every operator, so the stage is never entered

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `hostname`=FIN-WKS-605<br>`agent_ip`=10.42.196.43<br>`event_id`=4104<br>`image_path`=C:\Windows\System32\cmd.exe<br>… | carries no 'script_block_text' at all; evaluateCondition returns no-match for every operator on an absent field, so the stage gate rejects the event |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.196.43`

