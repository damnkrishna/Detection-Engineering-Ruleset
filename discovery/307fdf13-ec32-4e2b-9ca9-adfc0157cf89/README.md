# 307fdf13-ec32-4e2b-9ca9-adfc0157cf89 — golden replay datasets

`Backup Software Registry Key Modifications (AN0240-C)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'image_path not_regex .*\Q\services.exe\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'target_object contains HKLM\SOFTWARE\Veeam' — every other condition holds, so the stage gate rejects the events |

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


## Technique Breakdown

* What it is: Backup Software Discovery. Adversaries enumerate backup solutions installed on a host or domain to identify and subsequently disable or destroy backup data before launching ransomware or destructive attacks. Knowing which backup products are deployed (e.g. Veeam, Acronis, Windows Server Backup, ShadowProtect, CrashPlan) allows adversaries to target their specific service names, processes, or registry entries. Common enumeration methods include querying services (sc.exe query, tasklist.exe /SVC), registry (reg.exe query), or PowerShell WMI queries for known backup product names.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688), PowerShell Script Block Logs (Event ID 4104), and Registry Set Events (Sysmon Event ID 13).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 captures execution of sc.exe, reg.exe, wmic.exe, and PowerShell. Event ID 4104 logs script block details. Event ID 13 logs registry modifications.
    * Windows Security Logs: PARTIAL. Security logs EID 4688 captures command lines if enabled.
* Log Sources Covered:
    - Sysmon Event ID 1 (process_creation)
    - PowerShell Event ID 4104 (ps_script)
    - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
    - None.

## Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
