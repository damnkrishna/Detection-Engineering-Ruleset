# Proof — 55b5d20c-f8f1-4ac6-aff5-af97498c8992

## Rule

- **Rule ID:** 55b5d20c-f8f1-4ac6-aff5-af97498c8992
- **Rule name:** Exfiltration - Outbound Network Connection from Suspicious Path (AN0988)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [exfiltration] / [T1041]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `image_path` | image_path contains \AppData\Local\Temp\ | `C:\Windows\System32\AppData\Local\Temp\` |
| `dst_ip` | dst_ip not_starts_with 10. AND dst_ip not_starts_with 192.168. AND dst_ip not_starts_with 172.16. AND dst_ip not_starts_with 172.17. AND dst_ip not_starts_with 172.18. AND dst_ip not_starts_with 172.19. AND dst_ip not_starts_with 172.2 AND dst_ip not_starts_with 172.3 AND dst_ip not_starts_with 127. AND dst_ip not_starts_with 169.254. | `198.51.100.24` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\AppData\Local\Temp\<br>`dst_ip`=198.51.100.24<br>`hostname`=FIN-WKS-605<br>`agent_ip`=10.42.196.182<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.196.182`
- alert `045593d65d7f485784b14a35aca77e69` on lane `entity_key` = `10.42.196.182`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `image_path`=C:\Windows\System32\cmd.exe\Windows\Temp\<br>`dst_ip`=198.51.100.24<br>`hostname`=SEC-WKS-604<br>`agent_ip`=10.42.195.182<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.195.182`
- alert `f8855548fc37f4988a1f25bb20ae000a` on lane `entity_key` = `10.42.195.182`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'dst_ip not_starts_with 169.254.' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\AppData\Local\Temp\<br>`dst_ip`=169.254.198.51.100.24<br>`hostname`=FIN-WKS-605<br>`agent_ip`=10.42.196.182<br>… | dst_ip=169.254.198.51.100.24 fails 'dst_ip not_starts_with 169.254.' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.196.182`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path contains \AppData\Local\Temp\' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `image_path`=C:\Windows\System32\cmd.exe<br>`dst_ip`=198.51.100.24<br>`hostname`=FIN-WKS-605<br>`agent_ip`=10.42.196.182<br>… | image_path=C:\Windows\System32\cmd.exe fails 'image_path contains \AppData\Local\Temp\' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.196.182`

