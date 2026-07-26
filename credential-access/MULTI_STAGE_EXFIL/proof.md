# Proof — MULTI_STAGE_EXFIL

## Rule

- **Rule ID:** MULTI_STAGE_EXFIL
- **Rule name:** Credential access → collection → staging (optional) → exfiltration (Splunk: Cloud/Multi-stage Exfil story)
- **Rule shape:** SEQUENCE
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [suricata, wazuh]
- **Replay wire:** suricata on topic `replay-events-nids`
- **Correlation key:** `entity_key`
- **Window:** 14400s
- **Max gap:** _(not set)_
- **Stages:** 5
- **MITRE:** [TA0006, TA0008, TA0009, TA0010] / []
- **Behavioral constraints:** declared on the rule

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains credential | `ET MALWARE Observed Suspicious Outbound Connection credential` |

### Stage 1

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 3600 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains pass-the-hash | `C:\Windows\System32 pass-the-hash` |

### Stage 2

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic in_list [TA0009] | `TA0009` |

### Stage 3

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 3600 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains tar | `C:\Windows\SysWOW64 tar` |

### Stage 4

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic in_list [TA0010] | `TA0010` |
| `signature_name` | signature_name contains sftp | `ET MALWARE Observed Suspicious Outbound Connection sftp` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s) → stage 2 × 1 event(s) → stage 3 × 1 event(s) → stage 4 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection creden…<br>`hostname`=ENG-WKS-222<br>`agent_ip`=10.42.13.168<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +14400s (rule window); carries logon type 3 (network) — the remote-auth evidence this rule is gated on |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `signature_name`=C:\Windows\System32 pass-the-hash<br>`hostname`=ENG-WKS-222<br>`agent_ip`=10.42.13.168<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T09:35:00.000Z | 2 | `tactic`=TA0009<br>`hostname`=ENG-WKS-222<br>`agent_ip`=10.42.13.168<br>`severity_id`=3<br>… | satisfies every condition of stage 2; increments the count aggregate to 1/1 — the threshold event that completes stage 2 |
| 4 | 2026-03-02T09:40:00.000Z | 3 | `signature_name`=C:\Windows\SysWOW64 tar<br>`hostname`=ENG-WKS-222<br>`agent_ip`=10.42.13.168<br>`severity_id`=3<br>… | satisfies every condition of stage 3; increments the count aggregate to 1/1 — the threshold event that completes stage 3 |
| 5 | 2026-03-02T10:10:00.000Z | 4 | `tactic`=TA0010<br>`signature_name`=ET MALWARE Observed Suspicious Outbound Connection sftp<br>`hostname`=ENG-WKS-222<br>`agent_ip`=10.42.13.168<br>… | satisfies every condition of stage 4; increments the count aggregate to 1/1 — the threshold event that completes stage 4 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 5 of 5 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.13.168`
- alert `656c51ba98d3e48234b152ec3010d3db` on lane `entity_key` = `10.42.13.168`, match mode `SEQUENCE`, 5 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s) → stage 2 × 1 event(s) → stage 3 × 1 event(s) → stage 4 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 mimikatz<br>`hostname`=OPS-WKS-223<br>`agent_ip`=10.42.14.168<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +14400s (rule window); carries logon type 3 (network) — the remote-auth evidence this rule is gated on |
| 2 | 2026-03-02T10:05:00.000Z | 1 | `signature_name`=C:\Users\j.mercer\AppData\Local\Temp psexec<br>`hostname`=OPS-WKS-223<br>`agent_ip`=10.42.14.168<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T10:35:00.000Z | 2 | `tactic`=TA0009<br>`hostname`=OPS-WKS-223<br>`agent_ip`=10.42.14.168<br>`severity_id`=3<br>… | satisfies every condition of stage 2; increments the count aggregate to 1/1 — the threshold event that completes stage 2 |
| 4 | 2026-03-02T10:40:00.000Z | 3 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection compress<br>`hostname`=OPS-WKS-223<br>`agent_ip`=10.42.14.168<br>`severity_id`=3<br>… | satisfies every condition of stage 3; increments the count aggregate to 1/1 — the threshold event that completes stage 3 |
| 5 | 2026-03-02T11:10:00.000Z | 4 | `tactic`=TA0010<br>`signature_name`=C:\Windows\System32 dns tunnel<br>`hostname`=OPS-WKS-223<br>`agent_ip`=10.42.14.168<br>… | satisfies every condition of stage 4; increments the count aggregate to 1/1 — the threshold event that completes stage 4 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 5 of 5 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.14.168`
- alert `25cb2f8ef9dc88ee7bf4dbb2312582e6` on lane `entity_key` = `10.42.14.168`, match mode `SEQUENCE`, 5 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 4 | `tactic`=TA0010<br>`signature_name`=ET MALWARE Observed Suspicious Outbound Connection sftp<br>`hostname`=ENG-WKS-222<br>`agent_ip`=10.42.13.168<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection creden…<br>`hostname`=ENG-WKS-222<br>`agent_ip`=10.42.13.168<br>`severity_id`=3<br>… | completes stage 0, but the stage-4 evidence has already passed and is never replayed |
| 3 | 2026-03-02T09:00:02.000Z | 1 | `signature_name`=C:\Windows\System32 pass-the-hash<br>`hostname`=ENG-WKS-222<br>`agent_ip`=10.42.13.168<br>`severity_id`=3<br>… | completes stage 0, but the stage-4 evidence has already passed and is never replayed |
| 4 | 2026-03-02T09:00:03.000Z | 2 | `tactic`=TA0009<br>`hostname`=ENG-WKS-222<br>`agent_ip`=10.42.13.168<br>`severity_id`=3<br>… | completes stage 0, but the stage-4 evidence has already passed and is never replayed |
| 5 | 2026-03-02T09:00:04.000Z | 3 | `signature_name`=C:\Windows\SysWOW64 tar<br>`hostname`=ENG-WKS-222<br>`agent_ip`=10.42.13.168<br>`severity_id`=3<br>… | completes stage 0, but the stage-4 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 5 of 5 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.13.168`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection creden…<br>`hostname`=ENG-WKS-222<br>`agent_ip`=10.42.13.168<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +14400s (rule window); carries logon type 3 (network) — the remote-auth evidence this rule is gated on |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `signature_name`=C:\Windows\System32 pass-the-hash<br>`hostname`=ENG-WKS-222<br>`agent_ip`=10.42.13.168<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T09:35:00.000Z | 2 | `tactic`=TA0009<br>`hostname`=ENG-WKS-222<br>`agent_ip`=10.42.13.168<br>`severity_id`=3<br>… | satisfies every condition of stage 2; increments the count aggregate to 1/1 — the threshold event that completes stage 2 |
| 4 | 2026-03-02T09:40:00.000Z | 3 | `signature_name`=C:\Windows\SysWOW64 tar<br>`hostname`=ENG-WKS-222<br>`agent_ip`=10.42.13.168<br>`severity_id`=3<br>… | satisfies every condition of stage 3; increments the count aggregate to 1/1 — the threshold event that completes stage 3 |
| 5 | 2026-03-02T11:11:00.000Z | 4 | `tactic`=TA0010<br>`signature_name`=ET MALWARE Observed Suspicious Outbound Connection sftp<br>`hostname`=ENG-WKS-222<br>`agent_ip`=10.42.13.168<br>… | arrives 5460s after the previous stage completed, past the 3600s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 5 of 5 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.13.168`

