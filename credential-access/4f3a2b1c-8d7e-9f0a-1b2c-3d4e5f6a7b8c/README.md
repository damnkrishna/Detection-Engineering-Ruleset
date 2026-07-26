# 4f3a2b1c-8d7e-9f0a-1b2c-3d4e5f6a7b8c — golden replay datasets

`Suspicious AD FS Database Query for SAML Certificate Extraction via CLI (AN0420-A)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1606.002

* What it is: Forge Web Credentials: SAML Tokens (widely known as a Golden SAML attack). Adversaries who compromise an Identity Provider (IdP) like Active Directory Federation Services (AD FS) steal the token-signing certificate and the Distributed Key Manager (DKM) key. With these secrets, they can offline-forge perfectly valid SAML tokens. This allows them to bypass multi-factor authentication (MFA) and access federated cloud services (like Microsoft 365 or AWS) as any user in the domain.
* Log Source Requirements: Endpoint process execution, WMI querying, or file access monitoring on the AD FS server, and PowerShell script block logging (Sysmon Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 (Process Creation) can catch the attacker executing tools on the AD FS server to extract the certificates and keys from the Windows Internal Database (WID) or via PowerShell. Sysmon Event ID 4104 (Script Block) is effective at catching script-based queries.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: AD FS SAML certificate extraction attempts on local endpoints can be detected using process creation and PowerShell script block logs.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'parent_image not_regex .*\Q\setup.exe\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'cmd_line contains AdfsConfiguration' — every other condition holds, so the stage gate rejects the events |

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
