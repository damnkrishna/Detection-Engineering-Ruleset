# 28d70650-3536-4fe8-a1db-14e242c9665a — golden replay datasets

`LSA Security Packages Registry Modification (AN0757-C)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown
* What it is: Modify Authentication Process: Domain Controller Authentication. Adversaries patch domain controller authentication processes (specifically LSASS) to inject a "Skeleton Key," allowing them to authenticate as any user using a master password while legitimate authentication processes continue working normally.
* Log Source Requirements: Sysmon Process Access logs (Event ID 10), Sysmon Image Load logs (Event ID 7), and Sysmon Registry Set logs (Event ID 13).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Sysmon provides visibility into LSASS memory access, image loads, and registry changes on Domain Controllers.
  - NIDS (Suricata + Zeek): NO. Host-local system manipulation.
* Log Sources Covered:
  - Sysmon Event ID 10 (process_access)
  - Sysmon Event ID 7 (image_load)
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
| `benign_1.jsonl` | 0 | near-miss value for 'registry_new_value not_in_list [kerberos msv1_0 schannel wdigest tspkg pku2u credssp, kerberos msv1_0 schannel wdigest tspkg pku2u, kerberos msv1_0 schannel wdigest tspkg credssp]' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'target_object contains SYSTEM\CurrentControlSet\Control\Lsa\Security Packages' — every other condition holds, so the stage gate rejects the events |

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
