# 4bc0789f-5d87-43bb-86f3-637cef4eb0a0 — golden replay datasets

`Drive-by Compromise - Suspicious Child Process Spawned by Browser (AN0498-A)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1189

* What it is: Drive-by Compromise. Adversaries gain initial access by exploiting a user's web browser when they visit a compromised or malicious website. Successful browser exploitation is identified by the browser process (e.g., Chrome, Edge, Firefox) directly spawning shell interpreters, scripting hosts, binary loaders, or downloading and launching payloads from temporary user directories.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) capturing parent-child process relationships, and PowerShell script block logs (Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures browser processes spawning shell/script hosts. Sysmon Event ID 4104 (Script Block) is effective at catching scripting activity containing browser context references.
  * NIDS (Suricata + Zeek): YES. Network monitoring can identify downloads of binary payloads with anomalous headers or from high-risk domains, but host-based process monitoring is needed to verify execution.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Drive-by compromise execution can be detected using process creation and PowerShell script block logs.

## Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'image_path regex .*\Q\cmd.exe\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'parent_image regex .*\Q\chrome.exe\E$' — every other condition holds, so the stage gate rejects the events |

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
