# 1daa1b64-959b-4ea3-b4e8-85f7de2457ea — golden replay datasets

`Registry Modification of System Security Configurations (AN0781-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown

* What it is: Modify Registry. This involves adversaries modifying the Windows registry to achieve persistence, privilege escalation, or defense evasion. Specifically, targeting critical system settings like `Winlogon\Notify`, `Winlogon\Userinit`, and startup keys (`Run`, `RunOnce`) allows malicious binaries to load automatically on logon or boot. Disabling security settings like `SafeDllSearchMode` (forcing it to search the current working directory first) enables DLL hijacking attacks.
* Log Source Requirements: Telemetry focusing on process creation and command-line execution (specifically Windows CLI registry modification tools).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) captures execution of `reg.exe`, `powershell.exe`, or `wmic.exe` with command-line arguments targeting these keys. Wazuh scans these events to flag malicious registry commands.
* NIDS (Suricata + Zeek): NO. Registry modifications are local host-level configuration changes. They do not generate direct network traffic, making NIDS blind to the modification itself (though network telemetry might catch follow-on C2 traffic or the initial download of payloads).
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

## Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'target_object contains CurrentVersion\Winlogon\Notify' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | the field 'target_object' is absent entirely; an absent field is no-match for every operator, so the stage is never entered |

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
