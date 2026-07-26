# 5b747f72-9e46-4d1c-8eec-b4d4b477ec29 — golden replay datasets

`LSASS Process Access for Credential Replay (AN1144-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1550.002

* What it is: Use Alternate Authentication Material: Pass the Hash. Adversaries authenticate to remote systems using NTLM password hashes instead of cleartext passwords. By passing the hash directly to the local security provider (LSASS), they establish remote sessions without password knowledge. On Windows target systems, a successful Pass the Hash network logon is characterized by a Network Logon (Event ID 4624, Logon Type 3) using NTLM authentication where the Key Length is recorded as 0, because the normal NTLM challenge-response key derivation step is bypassed.
* Log Source Requirements: Windows Security Event Log Event ID 4624 (Logon) auditing NTLM parameters.
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Windows Security log captures Event ID 4624 details including Logon Type, Authentication Package, and Key Length. Wazuh parses and alerts on these fields.
  * NIDS (Suricata + Zeek): PARTIAL. Network sensors track NTLM sessions but cannot inspect the inner LSASS session parameters or key length structures.
* Log Sources Covered:
  - Windows Security Log Event ID 4624 (security)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Pass the hash activity can be detected using logon logs and process creation logs.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'cmd_line contains sekurlsa' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | the field 'cmd_line' is absent entirely; an absent field is no-match for every operator, so the stage is never entered |

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
