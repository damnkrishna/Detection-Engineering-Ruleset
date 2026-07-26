# Proof — f43e2a1b-7890-4c12-b345-6d7e8f9a0b1c

## Rule

- **Rule ID:** f43e2a1b-7890-4c12-b345-6d7e8f9a0b1c
- **Rule name:** Suspicious Remote Thread Creation (PE Injection) (AN0297)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [privilege-escalation, defense-evasion] / [T1055.002]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `target_image` | target_image regex .*\Q\explorer.exe\E$ | `C:\Windows\System32\explorer.exe` |
| `source_image` | source_image not_regex .*\Q\MsMpEng.exe\E$ AND source_image not_regex .*\Q\csrss.exe\E$ AND source_image not_regex .*\Q\wbemprox.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `target_image`=C:\Windows\System32\explorer.exe<br>`source_image`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-855<br>`agent_ip`=10.42.146.105<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; operates on a staging-directory path, which is what marks the process suspicious and backs the rule's high-rarity ATT&CK claim [T1055.002] |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.146.105`
- alert `0e7cc5ed7cc3d7b0d53ef3ba537be6a8` on lane `entity_key` = `10.42.146.105`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `target_image`=C:\Windows\System32\lsass.exe\svchost.exe<br>`source_image`=C:\Windows\System32\cmd.exe<br>`hostname`=HR-WKS-856<br>`agent_ip`=10.42.147.105<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; operates on a staging-directory path, which is what marks the process suspicious and backs the rule's high-rarity ATT&CK claim [T1055.002] |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.147.105`
- alert `33ecfd925c4456681d18d7d81a93a128` on lane `entity_key` = `10.42.147.105`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'source_image not_regex .*\Q\wbemprox.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `target_image`=C:\Windows\System32\explorer.exe<br>`source_image`=\wbemprox.exe<br>`hostname`=FIN-WKS-855<br>`agent_ip`=10.42.146.105<br>… | source_image=\wbemprox.exe fails 'source_image not_regex .*\Q\wbemprox.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.146.105`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_image regex .*\Q\explorer.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `target_image`=C:\Windows\System32\explorer.exe.bak<br>`source_image`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-855<br>`agent_ip`=10.42.146.105<br>… | target_image=C:\Windows\System32\explorer.exe.bak fails 'target_image regex .*\Q\explorer.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.146.105`

