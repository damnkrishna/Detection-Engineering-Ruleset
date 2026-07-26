# 4735f93d-9b15-407b-a148-9864c39bd81b — golden replay datasets

`Reversible Encryption Enabled via Active Directory Attribute modification (AN1621-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1556.005
* What it is: Modify Authentication Process: Reversible Encryption. Adversaries enable the "Store password using reversible encryption" setting (e.g. `UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED` in `userAccountControl`) for user accounts in Active Directory. This allows passwords to be stored as weakly encrypted ciphertexts, which can easily be decrypted to recover the user's plaintext password.
* Log Source Requirements: Windows Security Event logs (Event ID 4738 - User Account Changed, or Event ID 5136 - Directory Service Object Modified).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): NO. These are Active Directory changes audited via Windows Security Event Logs.
  - NIDS (Suricata + Zeek): NO. Encrypted AD LDAP or RPC traffic.
* Log Sources Covered:
  - Windows Security Event ID 4738 (service: security)
  - Windows Security Event ID 5136 (service: security)
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
| `benign_1.jsonl` | 0 | near-miss value for 'attribute_value in_list [640, 672, 66176, 66208, 2176, 4224, 8320, 0x280, 0x2A0, 0x10280, 0x102A0, 0x880, 0x1080, 0x2080]' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'attribute_ldapdisplay_name eq userAccountControl' — every other condition holds, so the stage gate rejects the events |

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
