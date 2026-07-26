# 5b6ec1c3-c896-43f4-ba87-e6517a8b04f3 — golden replay datasets

`MFA Registry Configuration Tampering (AN0543-A)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1556.006
* What it is: Modify Authentication Process: Multi-Factor Authentication. Adversaries modify MFA configurations or policies to bypass second-factor challenges. This includes modifying registry settings that govern Windows Hello PIN usage, disabling credential providers, or using administrative commands to clear or modify user MFA requirements in Active Directory / Azure AD.
* Log Source Requirements: Sysmon Registry Set events (Event ID 13) and PowerShell Script Block logging (Event ID 4104).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Sysmon logs registry modifications and PowerShell script block executions.
  - NIDS (Suricata + Zeek): NO. Host-local system changes and cloud provider administration APIs.
* Log Sources Covered:
  - Sysmon Event ID 13 (registry_set)
  - Sysmon Event ID 4104 (ps_script)
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
| `benign_1.jsonl` | 0 | near-miss value for 'target_object contains \Microsoft\Windows\System\PINLogin' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'registry_new_value eq DWORD (0x00000000)' — every other condition holds, so the stage gate rejects the events |

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
