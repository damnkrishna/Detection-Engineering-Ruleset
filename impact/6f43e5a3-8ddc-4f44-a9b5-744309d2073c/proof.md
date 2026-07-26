# Proof — 6f43e5a3-8ddc-4f44-a9b5-744309d2073c

## Rule

- **Rule ID:** 6f43e5a3-8ddc-4f44-a9b5-744309d2073c
- **Rule name:** Network Flooding Tools Execution (AN0969-A)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [impact] / [T1498.001]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id eq 1 | `1` |
| `original_filename` | original_filename in_list [loic.exe, hoic.exe, hping3.exe, nping.exe, ufonet.exe] | `loic.exe` |
| `image_path` | image_path regex .*\Q\loic.exe\E$ | `C:\Windows\System32\loic.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`original_filename`=loic.exe<br>`image_path`=C:\Windows\System32\loic.exe<br>`hostname`=FIN-WKS-770<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.61.154`
- alert `19ba9bf1a98bf15a4c563eff22c5c5ba` on lane `entity_key` = `10.42.61.154`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=1<br>`cmd_line`="C:\Windows\System32\cmd.exe" /c whoami hoic<br>`hostname`=SEC-WKS-769<br>`agent_ip`=10.42.60.154<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0 |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.60.154`
- alert `ab7d1ef1bc94ac9af721e9b6b492edfe` on lane `entity_key` = `10.42.60.154`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path regex .*\Q\loic.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`original_filename`=loic.exe<br>`image_path`=C:\Windows\System32\loic.exe.bak<br>`hostname`=FIN-WKS-770<br>… | image_path=C:\Windows\System32\loic.exe.bak fails 'image_path regex .*\Q\loic.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.61.154`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'original_filename in_list [loic.exe, hoic.exe, hping3.exe, nping.exe, ufonet.exe]' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=1<br>`original_filename`=loic.exe.bak<br>`image_path`=C:\Windows\System32\loic.exe<br>`hostname`=FIN-WKS-770<br>… | original_filename=loic.exe.bak fails 'original_filename in_list [loic.exe, hoic.exe, hping3.exe, nping.exe, ufonet.exe]' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.61.154`

