# 60e17140-3705-4539-bcea-94d22c9b73fe — golden replay datasets

`Service Installation of Unquoted Binary Path (AN0176-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1574.009

* What it is: Hijack Execution Flow: Path Interception by Unquoted Path. Adversaries exploit unquoted service binary paths containing spaces to escalate privileges or establish persistence. When Windows starts a service whose binary path contains spaces and is not enclosed in double quotes (e.g., `C:\Program Files\Custom App\service.exe`), it interprets the spaces as delimiters and attempts to execute files in sequence: first `C:\Program.exe`, then `C:\Program Files\Custom.exe`, and finally `C:\Program Files\Custom App\service.exe`. If an attacker writes a malicious payload to `C:\Program.exe`, it will execute with the service's high privileges (often SYSTEM).
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters (specifically targeting service configuration tools creating new services).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs the execution of `sc.exe` or PowerShell command-lines creating or editing service definitions.
* NIDS (Suricata + Zeek): NO. Creating or editing services is a local operating system administrative task. It generates no network logs.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Windows System Log Event ID 7045 (system)
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
| `benign_1.jsonl` | 0 | near-miss value for 'image_path not_contains "' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'event_id eq 7045' — every other condition holds, so the stage gate rejects the events |

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
