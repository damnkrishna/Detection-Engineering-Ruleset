# AN0287 — golden replay datasets

`Suspicious LSA Authentication Package Modification (AN0287)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1556

* What it is: Modify Authentication Process. Adversaries modify authentication mechanisms to bypass access controls or intercept credentials. Under this technique, adversaries register malicious DLLs as Password Filter DLLs or LSA packages (T1556.002). By modifying registry keys under the Local Security Authority (LSA), they configure LSA to load a malicious DLL. When users log in or modify their passwords, the malicious package intercepts credentials in cleartext.
* Log Source Requirements: Registry modification logs (Sysmon Event ID 13) tracking LSA packages keys and host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) tracking reg.exe command execution.
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 13 (Registry Set) is perfectly positioned to catch this modification. Sysmon Event ID 1 captures command-line registry tool usage.
  * Windows Security Logs: YES. Standard Security Logs capture registry write auditing if configured, and process execution command lines (Event ID 4688).
* Log Sources Covered:
  - Sysmon Event ID 13 (registry_set)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.
* Conclusion: LSA registry package modifications can be detected using registry events and command line logs.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'target_object contains \CurrentControlSet\Control\Lsa\Authentication Packages' — every other condition holds, so the stage gate rejects the events |
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
