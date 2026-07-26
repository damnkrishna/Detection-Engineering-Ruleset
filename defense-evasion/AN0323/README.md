# AN0323 — golden replay datasets

`Force Safe Mode Boot or Tamper SafeBoot Configuration (AN0323)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1688

* What it is: Safe Mode Boot. Adversaries force a system to boot into Windows Safe Mode to disable security features (like antivirus, EDRs, and network monitoring agents) that do not load in this minimal environment. Attackers achieve this by using the command-line utility `bcdedit.exe` to configure the system to boot into Safe Mode (`minimal` or `network`) on the next restart. Alternatively, they modify the registry keys under `SafeBoot` to allow their own malware or malicious drivers to execute even in Safe Mode.
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters (specifically targeting boot configuration and registry utilities).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs the execution of utilities like `bcdedit.exe` or `reg.exe` targeting boot configuration parameters.
* NIDS (Suricata + Zeek): NO. Configuring boot options is a local operating system administrative task. It generates no network telemetry.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'image_path regex .+\Q\bcdedit.exe\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'cmd_line contains safeboot' — every other condition holds, so the stage gate rejects the events |

## Replaying

These datasets must be replayed onto **`replay-events-sysmon`**.
The topic name is not cosmetic: `NormalizedEventDeserializer` selects its parser
from the topic, and `inferSourceFromTopic` derives `NormalizedEvent.source` — the
value `rule.isApplicableTo` gates on. Replayed onto a topic that resolves to a
different source, this rule cannot fire at all.

```
replay --file true_positive_1.jsonl --topic replay-events-sysmon
```

## Determinism

Timestamps anchor at a fixed origin (`2026-03-02T09:00:00.000Z`), identities derive from the rule id, and event uids are content-derived.
Regenerating from an unchanged rule reproduces these files byte for byte.
