# Proof — ea6a62c8-4f78-4cf1-a47c-6a718b773c04

## Rule

- **Rule ID:** ea6a62c8-4f78-4cf1-a47c-6a718b773c04
- **Rule name:** Exploit Public-Facing Application - Outbound Network Connection from Web Server (AN0219-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [initial-access] / [T1190]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `initiated` | initiated eq true | `true` |
| `image_path` | image_path regex .*\Q\w3wp.exe\E$ | `C:\Windows\System32\w3wp.exe` |
| `dst_ip` | dst_ip not_starts_with 127. AND dst_ip not_starts_with 169.254. AND dst_ip not_starts_with 10. AND dst_ip not_starts_with 172.16. AND dst_ip not_starts_with 172.17. AND dst_ip not_starts_with 172.18. AND dst_ip not_starts_with 172.19. AND dst_ip not_starts_with 172.20. AND dst_ip not_starts_with 172.21. AND dst_ip not_starts_with 172.22. AND dst_ip not_starts_with 172.23. AND dst_ip not_starts_with 172.24. AND dst_ip not_starts_with 172.25. AND dst_ip not_starts_with 172.26. AND dst_ip not_starts_with 172.27. AND dst_ip not_starts_with 172.28. AND dst_ip not_starts_with 172.29. AND dst_ip not_starts_with 172.30. AND dst_ip not_starts_with 172.31. AND dst_ip not_starts_with 192.168. AND dst_ip not_starts_with fe80: AND dst_ip not_starts_with ::1 | `198.51.100.24` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `initiated`=true<br>`image_path`=C:\Windows\System32\w3wp.exe<br>`dst_ip`=198.51.100.24<br>`hostname`=FIN-WKS-670<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.161.200`
- alert `d1a67030c877f8a204c31d8d8ba27e3a` on lane `entity_key` = `10.42.161.200`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `initiated`=true<br>`image_path`=C:\Windows\System32\cmd.exe\tomcat.exe<br>`dst_ip`=198.51.100.24<br>`hostname`=SEC-WKS-669<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.160.200`
- alert `a07188d12ea6b0ac3f2b21e24e5932e2` on lane `entity_key` = `10.42.160.200`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'dst_ip not_starts_with ::1' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `initiated`=true<br>`image_path`=C:\Windows\System32\w3wp.exe<br>`dst_ip`=::1198.51.100.24<br>`hostname`=FIN-WKS-670<br>… | dst_ip=::1198.51.100.24 fails 'dst_ip not_starts_with ::1' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.161.200`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\w3wp.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `initiated`=true<br>`image_path`=C:\Windows\System32\w3wp.exe.bak<br>`dst_ip`=198.51.100.24<br>`hostname`=FIN-WKS-670<br>… | image_path=C:\Windows\System32\w3wp.exe.bak fails 'image_path regex .*\Q\w3wp.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.161.200`

