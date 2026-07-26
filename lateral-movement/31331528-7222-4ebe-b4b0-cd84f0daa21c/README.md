# 31331528-7222-4ebe-b4b0-cd84f0daa21c — golden replay datasets

`Internal Spearphishing via PowerShell Script (AN0147-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'script_block_text contains Send-MailMessage' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | the field 'script_block_text' is absent entirely; an absent field is no-match for every operator, so the stage is never entered |

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

* What it is: Internal Spearphishing. Adversaries compromise a trusted internal user account and use it to send spearphishing emails containing malicious links or attachments to other employees inside the same organization. Since the sender is an internal employee, these emails successfully bypass standard external gateway email scanners. Detection focuses on identifying endpoints running scripts or automation commands (like PowerShell or C# SMTP wrappers) that initiate raw network connections to internal mail servers over SMTP/IMAP ports to send messages out-of-band.
* Log Source Requirements: Sysmon network connection logs (Event ID 3) tracking outbound connections from scripting or proxy execution binaries.
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 3 logs socket setups by local applications (like PowerShell or script hosts) targeting mail servers (ports 25, 587, 465). Wazuh aggregates these logs.
  * NIDS (Suricata + Zeek): YES. Network logs track SMTP headers and file attachments between internal IPs, which is highly effective for detecting internal propagation.
* Log Sources Covered:
  - Sysmon Event ID 3 (network_connection)
  - PowerShell Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Outbound SMTP connections initiated by non-standard scripting hosts and proxy binaries can be detected using Sysmon network connection logs.

## Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
