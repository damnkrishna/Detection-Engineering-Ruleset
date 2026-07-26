# Proof — 489e2402-b2da-4a55-894d-45db9129df8f

## Rule

- **Rule ID:** 489e2402-b2da-4a55-894d-45db9129df8f
- **Rule name:** Code Signing Policy Modification - Bcdedit DSE Disable (AN1446)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [defense-evasion] / [T1553.006]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_path` | image_path regex .*\Q\bcdedit.exe\E$ | `C:\Windows\System32\bcdedit.exe` |
| `cmd_line` | cmd_line contains loadoptions DDISABLE_INTEGRITY_CHECKS | `"C:\Windows\System32\cmd.exe" loadoptions DDISABLE_INTEGRITY_CHECKS` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\bcdedit.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" loadoptions DDISABLE_INTEGR…<br>`hostname`=SEC-WKS-404<br>`agent_ip`=10.42.95.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.95.82`
- alert `576e96daa8216d338d3303ae3279380a` on lane `entity_key` = `10.42.95.82`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `image_path`=C:\Windows\System32\cmd.exe\bcdedit.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami testsigning on<br>`hostname`=FIN-WKS-405<br>`agent_ip`=10.42.96.82<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.96.82`
- alert `d65a51de90a6a8c0502924f844076121` on lane `entity_key` = `10.42.96.82`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains loadoptions DDISABLE_INTEGRITY_CHECKS' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\bcdedit.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>`hostname`=SEC-WKS-404<br>`agent_ip`=10.42.95.82<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami fails 'cmd_line contains loadoptions DDISABLE_INTEGRITY_CHECKS' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.95.82`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\bcdedit.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\bcdedit.exe.bak<br>`cmd_line`="C:\Windows\System32\cmd.exe" loadoptions DDISABLE_INTEGR…<br>`hostname`=SEC-WKS-404<br>`agent_ip`=10.42.95.82<br>… | image_path=C:\Windows\System32\bcdedit.exe.bak fails 'image_path regex .*\Q\bcdedit.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.95.82`

