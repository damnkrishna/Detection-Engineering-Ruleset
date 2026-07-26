# Detection Engineering Test Datasets & Replay Benchmark

Deterministic replay datasets and standardized rule definitions derived from correlation and detection rules live on Kafka (`siem.correlation.rules`). 

Every dataset is systematically generated from the detection rule's own Intermediate Representation (IR), verified through the production ingest pipeline and detection engine, and packaged into standard MITRE ATT&CK tactic categories.

---

## 📊 Rule Coverage & Directory Summary

All **551 test datasets** are organized into standard MITRE ATT&CK tactic category subdirectories inside `datasets/`:

| Tactic / Classification | Folder Path | Datasets | Description |
|---|---|---|---|
| **Defense Evasion** | [`datasets/defense-evasion/`](./defense-evasion/) | 60 | Masquerading, process injection, signed binary proxying, anti-analysis |
| **Impact** | [`datasets/impact/`](./impact/) | 54 | Ransomware, data destruction, service stop, account wiping |
| **Execution** | [`datasets/execution/`](./execution/) | 46 | Command-line interpreters, script execution, LOLBin invocation |
| **Initial Access** | [`datasets/initial-access/`](./initial-access/) | 44 | Web application exploits, spearphishing payloads, drive-by compromise |
| **Collection** | [`datasets/collection/`](./collection/) | 42 | Staging files, archive creation, automated data gathering |
| **Lateral Movement** | [`datasets/lateral-movement/`](./lateral-movement/) | 36 | Remote service abuse, PsExec/WMI, ticket pass-the-hash/ticket |
| **Command and Control** | [`datasets/command-and-control/`](./command-and-control/) | 34 | C2 beacons, protocol tunneling, reverse shell callbacks, DGA |
| **Persistence** | [`datasets/persistence/`](./persistence/) | 34 | Registry run keys, scheduled tasks, WMI event subscriptions |
| **Discovery** | [`datasets/discovery/`](./discovery/) | 32 | Network scanning, group/user enumeration, share discovery |
| **Credential Access** | [`datasets/credential-access/`](./credential-access/) | 26 | Kerberoasting, AS-REP roasting, credential stuffing, LSASS dumping |
| **Exfiltration** | [`datasets/exfiltration/`](./exfiltration/) | 23 | DNS exfiltration, cloud storage uploads, multi-stage transfers |
| **Reconnaissance** | [`datasets/reconnaissance/`](./reconnaissance/) | 18 | Port scanning, OSINT, web path enumeration |
| **Privilege Escalation** | [`datasets/privilege-escalation/`](./privilege-escalation/) | 9 | Exploitation for privilege, token manipulation, UAC bypass |
| **Resource Development** | [`datasets/resource-development/`](./resource-development/) | 0 | Infrastructure acquisition, staging |
| **Uncategorized** | [`datasets/uncategorized/`](./uncategorized/) | 84 | Multi-tactic, composite behavioral, and general detection rules |
| **Unmapped** | [`datasets/unmapped/`](./unmapped/) | 9 | Test datasets currently pending source rule mapping |
| **Total Benchmark Coverage** | | **551** | **Complete coverage across 551 detection dataset folders** |

---

## 📁 Repository Layout

```
datasets/
├── README.md                      # Primary dataset benchmark documentation
├── <tactic-category>/             # e.g., execution, lateral-movement, persistence
│   └── <rule-folder>/             # e.g., LOLBIN_EXECUTION, AN0016, 00ccaca1-...
│       ├── rule.yml               # Complete Rule definition (Sigma YAML or IR_v1 JSON)
│       ├── true_positive_1.jsonl   # Primary True Positive telemetry (Exactly 1 expected alert)
│       ├── true_positive_2.jsonl   # Secondary True Positive scenario (Independent derivation)
│       ├── benign_1.jsonl          # True Negative telemetry (0 expected alerts - order failure)
│       ├── benign_2.jsonl          # True Negative telemetry (0 expected alerts - window/gap failure)
│       ├── expected.json           # Incident assertions & topic mapping metadata
│       ├── proof.md                # Per-event evidence trace table & engine evaluation proof
│       └── README.md               # Per-rule documentation & trigger rationale
└── unmapped/                       # Datasets pending source correlation rule definition
```

---

## 🚀 Replaying Datasets

### 1. Topic-Based Source Resolution

`NormalizedEventDeserializer` selects its parser and derives `NormalizedEvent.source` directly from the Kafka topic name. The `source` field is critical for `rule.isApplicableTo` and `matchesStage` evaluation gates.

Each dataset specifies its target topic in `expected.json` (`replay_topic`):

| Sensor Wire | Kafka Topic | Resolved `source` | Telemetry Format |
|---|---|---|---|
| **Windows EventLog / Sysmon** | `replay-events-sysmon` | `sysmon` | EDR envelope containing Sysmon EventLog XML (`xml`) |
| **HIDS (Host EDR / Wazuh)** | `replay-events-hids` | `wazuh` | JSON Lines (JSONL) flat canonical JSON |
| **NIDS (Network IDS / Suricata)** | `replay-events-nids` | `suricata` | JSON Lines (JSONL) flat canonical JSON |
| **Zeek Network Security Monitor** | `replay-events-zeek` | `zeek` | JSON Lines (JSONL) flat canonical JSON |

For the detection engine to consume datasets locally during development:
Add the target replay topics to `correlation.events.topics` in `dce-server/src/main/resources/config/application.properties`.

### 2. Regenerating Datasets with `dce-golden`

To re-run deterministic dataset generation and verification across all live rules:

```bash
mvn -pl dce-golden -am install -DskipTests
java -jar dce-golden/target/golden-gen.jar \
     --kafka-config kafka-rules.properties \
     --topic siem.correlation.rules \
     --out-dir datasets \
     --report DATASET_GENERATION_REPORT.md
```

Detailed generator coverage and blocker metrics are output to [`DATASET_GENERATION_REPORT.md`](../DATASET_GENERATION_REPORT.md).

---

## 🎯 Verification & Incident Counting Mechanics

### What `expected_alerts` Measures

`expected_alerts` counts **incidents, not raw alerts**. 

When a rule without an explicit `correlation_key` is evaluated across multiple entity lanes (`entity_key` and `src_ip`), a single detection fires as two alerts. In production, these are merged back into a single unified incident.

The dataset generator evaluates telemetry through `ProductionChainModel` — replicating cross-lane merges, deduplication cooldowns, and deterministic incident ID assignment. The incident count in `expected.json` matches what a SOC analyst sees in the SIEM console.

### Pipeline Verification Checks

Telemetry datasets are validated through a 3-step pipeline:

1. **`NormalizedEventDeserializer`**: Parses topic wire formats, maps fields, flags behavioral attributes, and synthesizes ATT&CK metadata.
2. **`MultiLaneRuleEvaluator`**: Executes lane fan-out matching `DynamicCorrelationEngine`, applying `IrRuleDispatcher` and `BehavioralValidationEngine` gates.
3. **`ProductionChainModel`**: Validates post-correlation incident aggregation and deduplication logic.

A dataset is accepted only if the observed incident count matches expectations **and** every telemetry event ingests without dead-letter errors.

---

## ⚡ Telemetry Pipeline & Engine Stress Testing Standard

All telemetry datasets in this benchmark adhere to the Master Operating Procedure:

1. **Format**: Telemetry events must be formatted as **JSON Lines (JSONL)** — one JSON object per line.
2. **Rule UID Injection**: Every event's `metadata` block includes `"rule_uid"` immediately following `"expected_alert"`:
   ```json
   "metadata": {
     "expected_alert": true,
     "rule_uid": "f1a2b3c4-d5e6-4f7a-8b9c-0d1e2f3a4b5c"
   }
   ```
3. **Dataset Separation**: Telemetry is cleanly separated into `True Positive Telemetry` (`expected_alert: true`) and `Benign Telemetry` (`expected_alert: false`).
4. **Engine Stress Mechanics**:
   - Every event includes epoch `time` timestamps.
   - Includes duplicate events for deduplication testing.
   - Includes schema boundary test cases (e.g. string vs int type coercion).
   - Includes optional block omissions (e.g. omitting `unmapped` objects).
