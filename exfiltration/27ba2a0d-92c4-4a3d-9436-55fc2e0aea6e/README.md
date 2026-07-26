# 27ba2a0d-92c4-4a3d-9436-55fc2e0aea6e — golden replay datasets

`Exfiltration - Outbound Unencrypted Connection by Scripting Host (AN0423)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown

* What it is: Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol. Adversaries bypass standard C2 communication channels to exfiltrate data using common, unencrypted protocols such as HTTP (port 80), FTP (port 21), or SMTP (port 25). They leverage built-in command-line tools or scripting engines to transmit staged archives to rogue external servers. Since the protocol is unencrypted, network analysis can read payloads, but host-based logs are necessary to identify the initiating processes.
* Log Source Requirements: Sysmon network connection logs (Event ID 3) combined with initiating process metadata (Sysmon Event ID 1).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 3 logs outbound TCP/UDP connections along with the parent process, source/destination ports, and IP addresses. Wazuh aggregates these events.
    * NIDS (Suricata + Zeek): YES. Zeek `http.log`, `ftp.log`, or `smtp.log` records unencrypted protocol transactions and file uploads in transit.

## Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'dst_ip not_starts_with 169.254.' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'image_path regex .*\Q\powershell.exe\E$' — every other condition holds, so the stage gate rejects the events |

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
