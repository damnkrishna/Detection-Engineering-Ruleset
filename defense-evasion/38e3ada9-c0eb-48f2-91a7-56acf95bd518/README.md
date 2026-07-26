# 38e3ada9-c0eb-48f2-91a7-56acf95bd518 — golden replay datasets

`Execution of DLL with Suspicious or Revoked Code Signature (AN0643-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'image_loaded contains \AppData\Local\Temp\' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'image_signature_status in_list [invalid, revoked, expired]' — every other condition holds, so the stage gate rejects the events |

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

* What it is: Code Signing. Adversaries abuse code signing to bypass security controls (like Windows Defender Application Control/AppLocker) that filter unsigned or untrusted binaries. They accomplish this by signing malicious code with stolen certificates, purchasing certificates using fake identities, or generating self-signed certificates and installing them into the victim's trusted root store.
* Log Source Requirements: Endpoint logs capturing process creation or module loads with associated digital signature metadata (e.g., Sysmon Event ID 7 for Image Load or Event ID 1 for Process Creation).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 7 (Image Loaded) captures the file signature status (`Signed`, `Signature`, `SignatureStatus`) for loaded DLLs and EXEs. Wazuh can parse this to alert on revoked or invalid states.
* NIDS (Suricata + Zeek): NO. Code signing validation is an endpoint-local cryptographic process. Network tools cannot verify the validity or signature status of binaries in transit.
* Log Sources Covered:
  - Sysmon Event ID 13 (registry_set)
  - Sysmon Event ID 7 (image_load)
* Log Sources Missing / Unused:
  - None.

## Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
