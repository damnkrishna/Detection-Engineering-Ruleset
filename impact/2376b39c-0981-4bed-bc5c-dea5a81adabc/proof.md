# Proof — 2376b39c-0981-4bed-bc5c-dea5a81adabc

## Rule

- **Rule ID:** 2376b39c-0981-4bed-bc5c-dea5a81adabc
- **Rule name:** Unauthorized Raw Disk Partition Access (AN0827-B)
- **Rule shape:** THRESHOLD
- **Rule origin / format:** sigma / SIGMA_v1
- **Event sources:** [sysmon]
- **Replay wire:** sysmon on topic `replay-events-sysmon`
- **Correlation key:** _(none — routes to the entity_key and src_ip lanes)_
- **Window:** 300s
- **Max gap:** _(not set)_
- **Stages:** 1
- **MITRE:** [impact] / [T1561.002]
- **Behavioral constraints:** _(none declared)_

## Stage requirements

### Stage 0

- Aggregate: `count`, threshold 1.0
- `within_seconds` = 300 (deadline for the next stage)
- Events required: 1

**Conditions the generator committed to**

| Field | Condition | Derived value |
|---|---|---|
| `event_id` | event_id eq 9 | `9` |
| `device` | device contains \PhysicalDrive | `FIN-WKS-014\PhysicalDrive` |
| `image_path` | image_path not_regex .*\Q\system32\svchost.exe\E$ AND image_path not_regex .*\Q\system32\csrss.exe\E$ AND image_path not_regex .*\Q\system32\lsass.exe\E$ AND image_path not_regex .*\Q\system32\defrag.exe\E$ AND image_path not_regex .*\Q\system32\chkdsk.exe\E$ AND image_path not_regex .*\Q\system32\WmiPrvSE.exe\E$ AND image_path not_regex .*\Q\vmnat.exe\E$ AND image_path not_regex .*\Q\vmtoolsd.exe\E$ AND image_path not_regex .*\Q\veeam.exe\E$ AND image_path not_regex .*\Q\backup.exe\E$ AND image_path not_regex .*\Q\acronis.exe\E$ | `C:\Windows\System32\cmd.exe` |

## true_positive_1

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=9<br>`device`=FIN-WKS-014\PhysicalDrive<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=HR-WKS-576<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; operates on a staging-directory path, which is what marks the process suspicious and backs the rule's high-rarity ATT&CK claim [T1561.002] |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.67.138`
- alert `5b3a6a4c4a43a4610f805e72000f65fd` on lane `entity_key` = `10.42.67.138`, match mode `THRESHOLD`, 1 matched event(s)

## true_positive_2

**Expected alerts:** 1  
**Construction:** THRESHOLD: stage 0 × 1 event(s)

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T10:00:00.000Z | 0 | `event_id`=9<br>`device`=C:\Windows\System32\Harddisk<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=FIN-WKS-575<br>… | satisfies every condition of stage 0; increments the count aggregate to 1/1 — the threshold event that completes stage 0; operates on a staging-directory path, which is what marks the process suspicious and backs the rule's high-rarity ATT&CK claim [T1561.002] |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 1
- production-comparable incidents: 1 (expected 1)
- resolved `source` = `sysmon`, lane key = `10.42.66.138`
- alert `b56aa35a176b276338650b0d873cbbbf` on lane `entity_key` = `10.42.66.138`, match mode `THRESHOLD`, 1 matched event(s)

## benign_1

**Expected alerts:** 0  
**Construction:** near-miss value for 'image_path not_regex .*\Q\acronis.exe\E$' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=9<br>`device`=FIN-WKS-014\PhysicalDrive<br>`image_path`=\acronis.exe<br>`hostname`=HR-WKS-576<br>… | image_path=\acronis.exe fails 'image_path not_regex .*\Q\acronis.exe\E$' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.67.138`

## benign_2

**Expected alerts:** 0  
**Construction:** near-miss value for 'device contains \PhysicalDrive' — every other condition holds, so the stage gate rejects the events

### Evidence table

| # | Event time | Stage | Key fields | Why this event exists |
|---|---|---|---|---|
| 1 | 2026-03-02T09:00:00.000Z | 0 | `event_id`=9<br>`device`=FIN-WKS-014\contoso-PhysicalDrive<br>`image_path`=C:\Windows\System32\cmd.exe<br>`hostname`=HR-WKS-576<br>… | device=FIN-WKS-014\contoso-PhysicalDrive fails 'device contains \PhysicalDrive' and every sibling branch on the same field, so IrConditionEvaluator.matchesStage returns false and the event is never counted |

### What the engine actually did

Replayed through `NormalizedEventDeserializer` on `replay-events-sysmon` and `MultiLaneRuleEvaluator`:

- events ingested: 1 of 1 lines (0 dead-lettered)
- raw interpreter alerts: 0
- production-comparable incidents: 0 (expected 0)
- resolved `source` = `sysmon`, lane key = `10.42.67.138`

