# 5213048d-466e-4f0d-a442-e0287b6d8324 — golden replay datasets

`Content Injection - Unauthorized Process Writing Web Content (AN0992-A)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1659

* What it is: Content Injection. Adversaries insert malicious content (such as scripts, redirection links, or iframes) into web pages or web application code. On Windows systems hosting web applications (e.g., IIS, Apache, or Nginx), this often manifests as unauthorized processes (such as scripting hosts, shells, or downloaded utilities) modifying or writing to files within the web server root directories (e.g., `C:\inetpub\wwwroot\`, `C:\xampp\htdocs\`).
* Log Source Requirements: Sysmon File Creation logs (Event ID 11), and Sysmon process creation logs (Event ID 1).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 11 tracks web content file modifications by non-standard processes. Sysmon Event ID 1 tracks administrative web server configuration modification tools.
  * NIDS (Suricata + Zeek): PARTIAL. Network monitoring can detect anomalous web requests or malicious scripts in transit, but cannot easily detect file-level writes to local disk paths.
* Log Sources Covered:
  - Sysmon Event ID 11 (file_event)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Content injection and configuration modification can be detected using file creation and process creation logs.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'image_path regex .*\Q\cmd.exe\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'file_path regex .*\Q.html\E$' — every other condition holds, so the stage gate rejects the events |

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
