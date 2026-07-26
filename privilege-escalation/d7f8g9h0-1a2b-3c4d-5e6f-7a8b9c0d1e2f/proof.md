# Proof — d7f8g9h0-1a2b-3c4d-5e6f-7a8b9c0d1e2f

## Rule

- **Rule ID:** d7f8g9h0-1a2b-3c4d-5e6f-7a8b9c0d1e2f
- **Rule name:** Suspicious Process Access for Memory Injection (AN0277)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [privilege-escalation, defense-evasion] / [T1055.004]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `granted_access` | granted_access in_list [0x1f0fff, 0x1438, 0x143a] | `0x1f0fff` |
| `target_image` | target_image regex .*\Q\explorer.exe\E$ | `C:\Windows\System32\explorer.exe` |
| `source_image` | source_image not_regex .*\Q\MsMpEng.exe\E$ AND source_image not_regex .*\Q\taskmgr.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `granted_access`=0x1f0fff<br>`target_image`=C:\Windows\System32\explorer.exe<br>`source_image`=C:\Windows\System32\cmd.exe<br>`hostname`=HR-WKS-636<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; operates on a staging-directory path, which is what marks the process suspicious and backs the rule's high-rarity ATT&CK claim [T1055.004] |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.27.54`
- alert `44c05e9df5df9ad278106545d1355b3b` on lane `entity_key` = `10.42.27.54`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `granted_access`=0x1438<br>`target_image`=C:\Windows\System32\lsass.exe\svchost.exe<br>`source_image`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-635<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; operates on a staging-directory path, which is what marks the process suspicious and backs the rule's high-rarity ATT&CK claim [T1055.004] |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.26.54`
- alert `1f877310ea0a478bce55aa93378c5b06` on lane `entity_key` = `10.42.26.54`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'source_image not_regex .*\Q\taskmgr.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `granted_access`=0x1f0fff<br>`target_image`=C:\Windows\System32\explorer.exe<br>`source_image`=\taskmgr.exe<br>`hostname`=HR-WKS-636<br>… | source_image=\taskmgr.exe fails 'source_image not_regex .*\Q\taskmgr.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.27.54`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'target_image regex .*\Q\explorer.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `granted_access`=0x1f0fff<br>`target_image`=C:\Windows\System32\explorer.exe.bak<br>`source_image`=C:\Windows\System32\cmd.exe<br>`hostname`=HR-WKS-636<br>… | target_image=C:\Windows\System32\explorer.exe.bak fails 'target_image regex .*\Q\explorer.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.27.54`

