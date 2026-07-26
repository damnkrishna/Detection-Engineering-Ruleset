# AN0320 — golden replay datasets

`Spearphishing via Service - Suspicious Child Process Spawned by Browser or Chat Application (AN0320)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1566.003

* What it is: Spearphishing via Service. Adversaries deliver spearphishing payloads or links via third-party web services (e.g., personal webmail like Gmail/Outlook, social media like LinkedIn/Twitter, or messaging platforms like Discord, Slack, Telegram, and Teams) rather than traditional enterprise email. This sub-technique bypasses enterprise email gateway controls. The detection focuses on identifying suspicious activity originating from web browser processes or chat/messaging applications, such as downloading and executing scripting interpreters, shells, or anomalous binaries.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) and PowerShell script block logs (Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures command-line execution and parent-child process relationships. Event ID 4104 (Script Block) captures PowerShell scripts running from downloads or temp paths.
  * NIDS (Suricata + Zeek): PARTIAL. Network monitoring can identify connections to known messaging API endpoints, but SSL/TLS encryption prevents payload inspection, making host-based endpoint logs essential.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Spearphishing via third-party services can be detected using process creation and PowerShell script block logs.

## Blind Spots & Tuning

- Legitimate user actions such as developer utilities running via local browser-based IDEs (e.g., Jupyter Notebooks or VS Code Web).
- Auto-update mechanisms for messaging applications that spawn command-line execution or self-update scripts.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'image_path regex .+\Q\cmd.exe\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'parent_image regex .+\Q\chrome.exe\E$' — every other condition holds, so the stage gate rejects the events |

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
