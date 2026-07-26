# Proof — APT_KILL_CHAIN

## Rule

- **Rule ID:** APT_KILL_CHAIN
- **Rule name:** Multi-stage APT: Recon (optional) → Initial Access → Execution → Evasion (optional) → Credential Access (optional) → Discovery (optional) → Persistence (optional) → Lateral (optional) → C2 (optional) → Exfil (optional)
- **Rule shape:** SEQUENCE
- **Rule origin / format:** cep-translated / IR_v1
- **Event sources:** [suricata, wazuh]
- **Replay wire:** suricata on topic `replay-events-nids`
- **Correlation key:** `entity_key`
- **Window:** 10800s
- **Max gap:** _(not set)_
- **Stages:** 10
- **MITRE:** [TA0043, TA0001, TA0002, TA0005, TA0006, TA0007, TA0003, TA0008, TA0011, TA0010] / []
- **Behavioral constraints:** declared on the rule

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains scan | `ET MALWARE Observed Suspicious Outbound Connection scan` |

### Stage 1

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains cve | `C:\Windows\System32 cve` |

### Stage 2

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `tactic` | tactic in_list [TA0002] | `TA0002` |

### Stage 3

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 1800 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains AMSI bypass | `C:\Windows\SysWOW64 AMSI bypass` |

### Stage 4

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 1800 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains kerberos | `ET MALWARE Observed Suspicious Outbound Connection kerberos` |

### Stage 5

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 1800 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains arp | `C:\Windows\System32 arp` |

### Stage 6

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 1800 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains CurrentVersion\Run | `C:\Users\j.mercer\AppData\Local\Temp CurrentVersion\Run` |

### Stage 7

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains logon type 3 | `C:\Windows\SysWOW64 logon type 3` |

### Stage 8

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains cobalt | `ET MALWARE Observed Suspicious Outbound Connection cobalt` |

### Stage 9

- Aggregate: `count`, threshold 1.0
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `signature_name` | signature_name contains mega | `C:\Windows\System32 mega` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s) → stage 2 × 1 event(s) → stage 3 × 1 event(s) → stage 4 × 1 event(s) → stage 5 × 1 event(s) → stage 6 × 1 event(s) → stage 7 × 1 event(s) → stage 8 × 1 event(s) → stage 9 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection scan<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +10800s (rule window); carries logon type 3 (network) — the remote-auth evidence this rule is gated on; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on; runs an execution-policy bypass out of a staging directory, which is what marks the process suspicious — the rule declares require_suspicious_process |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `signature_name`=C:\Windows\System32 cve<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T09:10:00.000Z | 2 | `tactic`=TA0002<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 2; increments the count aggregate to 1/1 — the threshold event that completes stage 2 |
| 4 | 2026-03-02T09:15:00.000Z | 3 | `signature_name`=C:\Windows\SysWOW64 AMSI bypass<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 3; increments the count aggregate to 1/1 — the threshold event that completes stage 3 |
| 5 | 2026-03-02T09:30:00.000Z | 4 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection kerberos<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 4; increments the count aggregate to 1/1 — the threshold event that completes stage 4 |
| 6 | 2026-03-02T09:45:00.000Z | 5 | `signature_name`=C:\Windows\System32 arp<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 5; increments the count aggregate to 1/1 — the threshold event that completes stage 5 |
| 7 | 2026-03-02T10:00:00.000Z | 6 | `signature_name`=C:\Users\j.mercer\AppData\Local\Temp CurrentVersion\Run<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 6; increments the count aggregate to 1/1 — the threshold event that completes stage 6 |
| 8 | 2026-03-02T10:15:00.000Z | 7 | `signature_name`=C:\Windows\SysWOW64 logon type 3<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 7; increments the count aggregate to 1/1 — the threshold event that completes stage 7 |
| 9 | 2026-03-02T10:20:00.000Z | 8 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection cobalt<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 8; increments the count aggregate to 1/1 — the threshold event that completes stage 8 |
| 10 | 2026-03-02T10:25:00.000Z | 9 | `signature_name`=C:\Windows\System32 mega<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 9; increments the count aggregate to 1/1 — the threshold event that completes stage 9 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 10 of 10 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.96.11`
- alert `5b20bcaa3a059c26e05889fc43ed89d3` on lane `entity_key` = `10.42.96.11`, match mode `SEQUENCE`, 10 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** SEQUENCE: stage 0 × 1 event(s) → stage 1 × 1 event(s) → stage 2 × 1 event(s) → stage 3 × 1 event(s) → stage 4 × 1 event(s) → stage 5 × 1 event(s) → stage 6 × 1 event(s) → stage 7 × 1 event(s) → stage 8 × 1 event(s) → stage 9 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `signature_name`=C:\Windows\System32 recon<br>`hostname`=HR-WKS-106<br>`agent_ip`=10.42.97.11<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +10800s (rule window); carries logon type 3 (network) — the remote-auth evidence this rule is gated on; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on; runs an execution-policy bypass out of a staging directory, which is what marks the process suspicious — the rule declares require_suspicious_process |
| 2 | 2026-03-02T10:05:00.000Z | 1 | `signature_name`=C:\Users\j.mercer\AppData\Local\Temp sqli<br>`hostname`=HR-WKS-106<br>`agent_ip`=10.42.97.11<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T10:10:00.000Z | 2 | `tactic`=TA0002<br>`hostname`=HR-WKS-106<br>`agent_ip`=10.42.97.11<br>`severity_id`=3<br>… | satisfies every condition of stage 2; increments the count aggregate to 1/1 — the threshold event that completes stage 2 |
| 4 | 2026-03-02T10:15:00.000Z | 3 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection Set-Mp…<br>`hostname`=HR-WKS-106<br>`agent_ip`=10.42.97.11<br>`severity_id`=3<br>… | satisfies every condition of stage 3; increments the count aggregate to 1/1 — the threshold event that completes stage 3 |
| 5 | 2026-03-02T10:30:00.000Z | 4 | `signature_name`=C:\Windows\System32 ticket<br>`hostname`=HR-WKS-106<br>`agent_ip`=10.42.97.11<br>`severity_id`=3<br>… | satisfies every condition of stage 4; increments the count aggregate to 1/1 — the threshold event that completes stage 4 |
| 6 | 2026-03-02T10:45:00.000Z | 5 | `signature_name`=C:\Users\j.mercer\AppData\Local\Temp ldap query<br>`hostname`=HR-WKS-106<br>`agent_ip`=10.42.97.11<br>`severity_id`=3<br>… | satisfies every condition of stage 5; increments the count aggregate to 1/1 — the threshold event that completes stage 5 |
| 7 | 2026-03-02T11:00:00.000Z | 6 | `signature_name`=C:\Windows\SysWOW64 startup<br>`hostname`=HR-WKS-106<br>`agent_ip`=10.42.97.11<br>`severity_id`=3<br>… | satisfies every condition of stage 6; increments the count aggregate to 1/1 — the threshold event that completes stage 6 |
| 8 | 2026-03-02T11:15:00.000Z | 7 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection 4624<br>`hostname`=HR-WKS-106<br>`agent_ip`=10.42.97.11<br>`severity_id`=3<br>… | satisfies every condition of stage 7; increments the count aggregate to 1/1 — the threshold event that completes stage 7 |
| 9 | 2026-03-02T11:20:00.000Z | 8 | `signature_name`=C:\Windows\System32 metasploit<br>`hostname`=HR-WKS-106<br>`agent_ip`=10.42.97.11<br>`severity_id`=3<br>… | satisfies every condition of stage 8; increments the count aggregate to 1/1 — the threshold event that completes stage 8 |
| 10 | 2026-03-02T11:25:00.000Z | 9 | `signature_name`=C:\Users\j.mercer\AppData\Local\Temp exfil<br>`hostname`=HR-WKS-106<br>`agent_ip`=10.42.97.11<br>`severity_id`=3<br>… | satisfies every condition of stage 9; increments the count aggregate to 1/1 — the threshold event that completes stage 9 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 10 of 10 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `suricata`, lane key = `10.42.97.11`
- alert `6f41678c50a48195a3b38c59e8970e13` on lane `entity_key` = `10.42.97.11`, match mode `SEQUENCE`, 10 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** stage order inverted — the final stage's events precede the stage-0 completion, so IrSequenceEvaluator never advances past stage 0

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 9 | `signature_name`=C:\Windows\System32 mega<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | arrives before stage 0 has completed; IrSequenceEvaluator only evaluates state.currentStage (0), so a final-stage event at this point is ignored |
| 2 | 2026-03-02T09:00:01.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection scan<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | completes stage 0, but the stage-9 evidence has already passed and is never replayed |
| 3 | 2026-03-02T09:00:02.000Z | 1 | `signature_name`=C:\Windows\System32 cve<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | completes stage 0, but the stage-9 evidence has already passed and is never replayed |
| 4 | 2026-03-02T09:00:03.000Z | 2 | `tactic`=TA0002<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | completes stage 0, but the stage-9 evidence has already passed and is never replayed |
| 5 | 2026-03-02T09:00:04.000Z | 3 | `signature_name`=C:\Windows\SysWOW64 AMSI bypass<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | completes stage 0, but the stage-9 evidence has already passed and is never replayed |
| 6 | 2026-03-02T09:00:05.000Z | 4 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection kerberos<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | completes stage 0, but the stage-9 evidence has already passed and is never replayed |
| 7 | 2026-03-02T09:00:06.000Z | 5 | `signature_name`=C:\Windows\System32 arp<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | completes stage 0, but the stage-9 evidence has already passed and is never replayed |
| 8 | 2026-03-02T09:00:07.000Z | 6 | `signature_name`=C:\Users\j.mercer\AppData\Local\Temp CurrentVersion\Run<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | completes stage 0, but the stage-9 evidence has already passed and is never replayed |
| 9 | 2026-03-02T09:00:08.000Z | 7 | `signature_name`=C:\Windows\SysWOW64 logon type 3<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | completes stage 0, but the stage-9 evidence has already passed and is never replayed |
| 10 | 2026-03-02T09:00:09.000Z | 8 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection cobalt<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | completes stage 0, but the stage-9 evidence has already passed and is never replayed |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 10 of 10 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.96.11`

## benign_2

**Expected alerts:** 0  
**Construction:** inter-stage gap exceeds the window the rule allows, so the stage transition is rejected and the partial match is discarded

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection scan<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; starts the stage-1 deadline timer at +10800s (rule window); carries logon type 3 (network) — the remote-auth evidence this rule is gated on; carries both connection endpoints, the network indicator the rule's declared TA0011 tactic is gated on; runs an execution-policy bypass out of a staging directory, which is what marks the process suspicious — the rule declares require_suspicious_process |
| 2 | 2026-03-02T09:05:00.000Z | 1 | `signature_name`=C:\Windows\System32 cve<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 1; increments the count aggregate to 1/1 — the threshold event that completes stage 1 |
| 3 | 2026-03-02T09:10:00.000Z | 2 | `tactic`=TA0002<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 2; increments the count aggregate to 1/1 — the threshold event that completes stage 2 |
| 4 | 2026-03-02T09:15:00.000Z | 3 | `signature_name`=C:\Windows\SysWOW64 AMSI bypass<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 3; increments the count aggregate to 1/1 — the threshold event that completes stage 3 |
| 5 | 2026-03-02T09:30:00.000Z | 4 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection kerberos<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 4; increments the count aggregate to 1/1 — the threshold event that completes stage 4 |
| 6 | 2026-03-02T09:45:00.000Z | 5 | `signature_name`=C:\Windows\System32 arp<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 5; increments the count aggregate to 1/1 — the threshold event that completes stage 5 |
| 7 | 2026-03-02T10:00:00.000Z | 6 | `signature_name`=C:\Users\j.mercer\AppData\Local\Temp CurrentVersion\Run<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 6; increments the count aggregate to 1/1 — the threshold event that completes stage 6 |
| 8 | 2026-03-02T10:15:00.000Z | 7 | `signature_name`=C:\Windows\SysWOW64 logon type 3<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 7; increments the count aggregate to 1/1 — the threshold event that completes stage 7 |
| 9 | 2026-03-02T10:20:00.000Z | 8 | `signature_name`=ET MALWARE Observed Suspicious Outbound Connection cobalt<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | satisfies every condition of stage 8; increments the count aggregate to 1/1 — the threshold event that completes stage 8 |
| 10 | 2026-03-02T10:36:00.000Z | 9 | `signature_name`=C:\Windows\System32 mega<br>`hostname`=FIN-WKS-105<br>`agent_ip`=10.42.96.11<br>`severity_id`=3<br>… | arrives 960s after the previous stage completed, past the 600s inter-stage bound, so the evaluator resets the partial match |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-nids` and `MultiLaneRuleEvaluator`:

- events ingested: 10 of 10 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `suricata`, lane key = `10.42.96.11`

