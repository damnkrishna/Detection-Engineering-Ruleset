# Proof — f432a1bb-9087-4c12-b345-6d7e8f9a011c

## Rule

- **Rule ID:** f432a1bb-9087-4c12-b345-6d7e8f9a011c
- **Rule name:** Suspicious Process Access indicating EWM Injection (AN0608)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [privilege-escalation, defense-evasion] / [T1055.011]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `granted_access` | granted_access in_list [0x1F0FFF, 0x143A] | `0x1F0FFF` |
| `target_image` | target_image regex .*\Q\explorer.exe\E$ | `C:\Windows\System32\explorer.exe` |
| `source_image` | source_image not_regex .*\Q\taskmgr.exe\E$ AND source_image not_regex .*\Q\MsMpEng.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `granted_access`=0x1F0FFF<br>`target_image`=C:\Windows\System32\explorer.exe<br>`source_image`=C:\Windows\System32\cmd.exe<br>`hostname`=OPS-WKS-643<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; operates on a staging-directory path, which is what marks the process suspicious and backs the rule's high-rarity ATT&CK claim [T1055.011] |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.34.207`
- alert `54268c514ac75cdb1c235596d5dea71f` on lane `entity_key` = `10.42.34.207`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `granted_access`=0x143A<br>`target_image`=C:\Windows\System32\lsass.exe\dwm.exe<br>`source_image`=C:\Windows\System32\cmd.exe<br>`hostname`=ENG-WKS-642<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; operates on a staging-directory path, which is what marks the process suspicious and backs the rule's high-rarity ATT&CK claim [T1055.011] |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.33.207`
- alert `0da93ffaed993923c8970ae1d3dc0abf` on lane `entity_key` = `10.42.33.207`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'source_image not_regex .*\Q\MsMpEng.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `granted_access`=0x1F0FFF<br>`target_image`=C:\Windows\System32\explorer.exe<br>`source_image`=\MsMpEng.exe<br>`hostname`=OPS-WKS-643<br>… | source_image=\MsMpEng.exe fails 'source_image not_regex .*\Q\MsMpEng.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.34.207`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_image regex .*\Q\explorer.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `granted_access`=0x1F0FFF<br>`target_image`=C:\Windows\System32\explorer.exe.bak<br>`source_image`=C:\Windows\System32\cmd.exe<br>`hostname`=OPS-WKS-643<br>… | target_image=C:\Windows\System32\explorer.exe.bak fails 'target_image regex .*\Q\explorer.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.34.207`

