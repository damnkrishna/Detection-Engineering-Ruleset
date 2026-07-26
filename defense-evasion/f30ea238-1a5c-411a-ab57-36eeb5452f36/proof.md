# Proof — f30ea238-1a5c-411a-ab57-36eeb5452f36

## Rule

- **Rule ID:** f30ea238-1a5c-411a-ab57-36eeb5452f36
- **Rule name:** Clear Windows Event Logs - CLI Utilities (AN1472)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [defense-evasion] / [T1685.005]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_path` | image_path regex .*\Q\wevtutil.exe\E$ | `C:\Windows\System32\wevtutil.exe` |
| `cmd_line` | cmd_line contains cl AND cmd_line contains Security | `"C:\Windows\System32\cmd.exe" cl Security` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\wevtutil.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" cl Security<br>`hostname`=OPS-WKS-153<br>`agent_ip`=10.42.144.112<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.144.112`
- alert `7a160ff3f1f03b46c72d1e5d4bd69d2f` on lane `entity_key` = `10.42.144.112`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `image_path`=C:\Windows\System32\cmd.exe\pwsh.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami Remove-EventLog<br>`hostname`=SEC-WKS-154<br>`agent_ip`=10.42.145.112<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.145.112`
- alert `ed795945694fbbd69ae35c30e26e2a7f` on lane `entity_key` = `10.42.145.112`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains Security' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\wevtutil.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>`hostname`=OPS-WKS-153<br>`agent_ip`=10.42.144.112<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami fails 'cmd_line contains Security' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.144.112`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\wevtutil.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\wevtutil.exe.bak<br>`cmd_line`="C:\Windows\System32\cmd.exe" cl Security<br>`hostname`=OPS-WKS-153<br>`agent_ip`=10.42.144.112<br>… | image_path=C:\Windows\System32\wevtutil.exe.bak fails 'image_path regex .*\Q\wevtutil.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.144.112`

