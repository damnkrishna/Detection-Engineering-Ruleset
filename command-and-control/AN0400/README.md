# AN0400 — golden replay datasets

`Cryptographic DLL Loaded by Non-Cryptographic Process (AN0400)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1573.001

* What it is: Encrypted Channel: Symmetric Cryptography. Adversaries encrypt their Command and Control (C2) traffic using symmetric encryption algorithms (e.g., AES or RC4) to evade signature-based network inspection. Malware binaries running on Windows often call built-in cryptographic libraries (CNG/CryptoAPI) by loading DLLs such as bcryptprimitives.dll, bcrypt.dll, or cryptsp.dll. When non-cryptographic system binaries (like calc.exe or notepad.exe) load these DLLs and subsequently open network sockets, it indicates process injection and custom C2 encryption.
* Log Source Requirements: Endpoint image load logs (Sysmon Event ID 7 / Windows Security Event ID 5056) and Network Connection logs (Sysmon Event ID 3).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 7 captures DLL loading events. Event ID 3 logs outbound network connections.
    * Windows Security Logs: PARTIAL. Security logs Event ID 5056 captures image loads if configured.
* Log Sources Covered:
    - Sysmon Event ID 7 (image_load)
    - Sysmon Event ID 3 (network_connection)
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
| `benign_1.jsonl` | 0 | near-miss value for 'image_loaded regex .+\Q\bcrypt.dll\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'image_path regex .+\Q\calc.exe\E$' — every other condition holds, so the stage gate rejects the events |

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
