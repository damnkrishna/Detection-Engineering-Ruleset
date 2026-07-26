# Proof — AN0118

## Rule

- **Rule ID:** AN0118
- **Rule name:** Verclsid LOLBin Abuse for COM Object Execution (AN0118)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / IR_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [defense-evasion] / [T1218.012]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_path` | image_path regex .+\Q\verclsid.exe\E$ | `C:\Windows\System32\verclsid.exe` |
| `cmd_line` | cmd_line contains  /S  | `"C:\Windows\System32\cmd.exe"  /S C:\Users\Public\export.dat` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\verclsid.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe"  /S C:\Users\Public\export.dat<br>`hostname`=FIN-WKS-360<br>`agent_ip`=10.42.151.151<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.151.151`
- alert `f19f6e3e2564fe46dcd5665cad1aa7a4` on lane `entity_key` = `10.42.151.151`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `original_filename`=verclsid.exe<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami /C<br>`hostname`=SEC-WKS-359<br>`agent_ip`=10.42.150.151<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.150.151`
- alert `c8049f8246f4da6bdc358caae64a1951` on lane `entity_key` = `10.42.150.151`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'cmd_line contains  /S ' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\verclsid.exe<br>`cmd_line`="C:\Program Files\Contoso\Reporting\contoso-report.exe" -…<br>`hostname`=FIN-WKS-360<br>`agent_ip`=10.42.151.151<br>… | cmd_line="C:\Program Files\Contoso\Reporting\contoso-report.exe" --daily fails 'cmd_line contains  /S ' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.151.151`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .+\Q\verclsid.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\verclsid.exe.bak<br>`cmd_line`="C:\Windows\System32\cmd.exe"  /S C:\Users\Public\export.dat<br>`hostname`=FIN-WKS-360<br>`agent_ip`=10.42.151.151<br>… | image_path=C:\Windows\System32\verclsid.exe.bak fails 'image_path regex .+\Q\verclsid.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.151.151`

