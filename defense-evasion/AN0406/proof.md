# Proof — AN0406

## Rule

- **Rule ID:** AN0406
- **Rule name:** Disabling or Tampering with Windows Firewall (AN0406)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [defense-evasion] / [T1686]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `cmd_line` | cmd_line contains advfirewall AND cmd_line contains set AND cmd_line contains state AND cmd_line contains off | `"C:\Windows\System32\cmd.exe" advfirewall set state off` |
| `image_path` | image_path regex .+\Q\netsh.exe\E$ | `C:\Windows\System32\netsh.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe" advfirewall set state off<br>`image_path`=C:\Windows\System32\netsh.exe<br>`hostname`=FIN-WKS-210<br>`agent_ip`=10.42.101.57<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.101.57`
- alert `ddfebacac6ecb89b3cc0b8010dab9aa9` on lane `entity_key` = `10.42.101.57`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `original_filename`=pwsh.dll<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami Disable-NetFirewa…<br>`hostname`=SEC-WKS-209<br>`agent_ip`=10.42.100.57<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.100.57`
- alert `24c35f94cd80d928849eb260415e1920` on lane `entity_key` = `10.42.100.57`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .+\Q\netsh.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe" advfirewall set state off<br>`image_path`=C:\Windows\System32\netsh.exe.bak<br>`hostname`=FIN-WKS-210<br>`agent_ip`=10.42.101.57<br>… | image_path=C:\Windows\System32\netsh.exe.bak fails 'image_path regex .+\Q\netsh.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.101.57`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains off' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `cmd_line`="C:\Windows\System32\cmd.exe" /c whoami<br>`image_path`=C:\Windows\System32\netsh.exe<br>`hostname`=FIN-WKS-210<br>`agent_ip`=10.42.101.57<br>… | cmd_line="C:\Windows\System32\cmd.exe" /c whoami fails 'cmd_line contains off' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.101.57`

