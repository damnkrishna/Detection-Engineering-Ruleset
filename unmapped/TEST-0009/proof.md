# Proof — TEST-0009

## Rule

- **Rule ID:** TEST-0009
- **Rule name:** Multi-Stage Credential Theft
- **Rule shape:** SEQUENCE
- **Rule origin / format:** sigma / SIGMA_v2E
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 1200s
- **Max gap:** _(not set)_
- **Stages:** 5
- **MITRE:** [] / []
- **Behavioral constraints:** declared on the rule

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 1200 (deadline for the next stage)
- Stage correlation key: `host.name`
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_path` | image_path regex .*\Q\powershell.exe\E$ | `C:\Windows\System32\powershell.exe` |

### Stage 1

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 1200 (deadline for the next stage)
- Stage correlation key: `host.name`
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `cmd_line` | cmd_line contains sekurlsa | `"C:\Windows\System32\cmd.exe" /c whoami sekurlsa` |

### Stage 2

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 1200 (deadline for the next stage)
- Stage correlation key: `host.name`
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `target_image` | target_image regex .*\Q\lsass.exe\E$ | `C:\Windows\System32\lsass.exe` |

### Stage 3

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 1200 (deadline for the next stage)
- Stage correlation key: `host.name`
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic eq TA0011 | `TA0011` |

### Stage 4

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 1200 (deadline for the next stage)
- Stage correlation key: `host.name`
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_path` | image_path regex .*\Q\schtasks.exe\E$ | `C:\Windows\SysWOW64\schtasks.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s) → stage 2 × 1 event(s) → stage 3 × 1 event(s) → stage 4 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\powershell.exe<br>`hostname`=SEC-WKS-279<br>`agent_ip`=10.42.170.111<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1200s (within_seconds); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:10:00.000Z | 1 | `cmd_line`="C:\Windows\System32\cmd.exe" /c whoami sekurlsa<br>`hostname`=SEC-WKS-279<br>`agent_ip`=10.42.170.111<br>`event_id`=1<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T09:20:00.000Z | 2 | `target_image`=C:\Windows\System32\lsass.exe<br>`hostname`=SEC-WKS-279<br>`agent_ip`=10.42.170.111<br>`event_id`=10<br>… | satisfies every condition of stage 2; increments the count aggregate to 1/1 — the threshold event that completes stage 2 |
| 4 | 2026-03-02T09:30:00.000Z | 3 | `tactic`=TA0011<br>`hostname`=SEC-WKS-279<br>`agent_ip`=10.42.170.111<br>`event_id`=1<br>… | satisfies every condition of stage 3; increments the count aggregate to 1/1 — the threshold event that completes stage 3 |
| 5 | 2026-03-02T09:40:00.000Z | 4 | `image_path`=C:\Windows\SysWOW64\schtasks.exe<br>`hostname`=SEC-WKS-279<br>`agent_ip`=10.42.170.111<br>`event_id`=1<br>… | satisfies every condition of stage 4; increments the count aggregate to 1/1 — the threshold event that completes stage 4 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 5 of 5 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.170.111`
- alert `2a276758d82a5f90d1e54211ad4d727d` on lane `entity_key` = `10.42.170.111`, match mode `SEQUENCE`, 5 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s) → stage 2 × 1 event(s) → stage 3 × 1 event(s) → stage 4 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `image_path`=C:\Windows\System32\cmd.exe\powershell.exe<br>`hostname`=FIN-WKS-280<br>`agent_ip`=10.42.171.111<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1200s (within_seconds); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T10:10:00.000Z | 1 | `cmd_line`=C:\Windows\System32 sekurlsa<br>`hostname`=FIN-WKS-280<br>`agent_ip`=10.42.171.111<br>`event_id`=1<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T10:20:00.000Z | 2 | `target_image`=C:\Users\j.mercer\AppData\Local\Temp\lsass.exe<br>`hostname`=FIN-WKS-280<br>`agent_ip`=10.42.171.111<br>`event_id`=10<br>… | satisfies every condition of stage 2; increments the count aggregate to 1/1 — the threshold event that completes stage 2 |
| 4 | 2026-03-02T10:30:00.000Z | 3 | `tactic`=TA0011<br>`hostname`=FIN-WKS-280<br>`agent_ip`=10.42.171.111<br>`event_id`=1<br>… | satisfies every condition of stage 3; increments the count aggregate to 1/1 — the threshold event that completes stage 3 |
| 5 | 2026-03-02T10:40:00.000Z | 4 | `image_path`=C:\Windows\System32\schtasks.exe<br>`hostname`=FIN-WKS-280<br>`agent_ip`=10.42.171.111<br>`event_id`=1<br>… | satisfies every condition of stage 4; increments the count aggregate to 1/1 — the threshold event that completes stage 4 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 5 of 5 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.171.111`
- alert `77dd1b772ccd9c4fd478e52989e99e61` on lane `entity_key` = `10.42.171.111`, match mode `SEQUENCE`, 5 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 4 | `image_path`=C:\Windows\SysWOW64\schtasks.exe<br>`hostname`=SEC-WKS-279<br>`agent_ip`=10.42.170.111<br>`event_id`=1<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `image_path`=C:\Windows\System32\powershell.exe<br>`hostname`=SEC-WKS-279<br>`agent_ip`=10.42.170.111<br>`event_id`=1<br>… | completes stage 0, but the stage-4 evidence has already passed and is never replayed |
| 3 | 2026-03-02T09:00:02.000Z | 1 | `cmd_line`="C:\Windows\System32\cmd.exe" /c whoami sekurlsa<br>`hostname`=SEC-WKS-279<br>`agent_ip`=10.42.170.111<br>`event_id`=1<br>… | completes stage 0, but the stage-4 evidence has already passed and is never replayed |
| 4 | 2026-03-02T09:00:03.000Z | 2 | `target_image`=C:\Windows\System32\lsass.exe<br>`hostname`=SEC-WKS-279<br>`agent_ip`=10.42.170.111<br>`event_id`=10<br>… | completes stage 0, but the stage-4 evidence has already passed and is never replayed |
| 5 | 2026-03-02T09:00:04.000Z | 3 | `tactic`=TA0011<br>`hostname`=SEC-WKS-279<br>`agent_ip`=10.42.170.111<br>`event_id`=1<br>… | completes stage 0, but the stage-4 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 5 of 5 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.170.111`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\powershell.exe<br>`hostname`=SEC-WKS-279<br>`agent_ip`=10.42.170.111<br>`event_id`=1<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +1200s (within_seconds); carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on |
| 2 | 2026-03-02T09:10:00.000Z | 1 | `cmd_line`="C:\Windows\System32\cmd.exe" /c whoami sekurlsa<br>`hostname`=SEC-WKS-279<br>`agent_ip`=10.42.170.111<br>`event_id`=1<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T09:20:00.000Z | 2 | `target_image`=C:\Windows\System32\lsass.exe<br>`hostname`=SEC-WKS-279<br>`agent_ip`=10.42.170.111<br>`event_id`=10<br>… | satisfies every condition of stage 2; increments the count aggregate to 1/1 — the threshold event that completes stage 2 |
| 4 | 2026-03-02T09:30:00.000Z | 3 | `tactic`=TA0011<br>`hostname`=SEC-WKS-279<br>`agent_ip`=10.42.170.111<br>`event_id`=1<br>… | satisfies every condition of stage 3; increments the count aggregate to 1/1 — the threshold event that completes stage 3 |
| 5 | 2026-03-02T10:01:00.000Z | 4 | `image_path`=C:\Windows\SysWOW64\schtasks.exe<br>`hostname`=SEC-WKS-279<br>`agent_ip`=10.42.170.111<br>`event_id`=1<br>… | arrives 1860s after the previous stage completed, past the 1200s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 5 of 5 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.170.111`

