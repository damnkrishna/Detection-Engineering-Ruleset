# 1b9c493c-9dfb-4624-bb63-83e476b3c64b — golden replay datasets

`Permissions Modification via Script Block (AN0834-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown

* What it is: File and Directory Permissions Modification. Adversaries modify file and directory permissions (DACLs) and attributes to bypass access controls, escalate privileges, or evade detection. They use built-in Windows utilities like `icacls`, `cacls`, `takeown`, and `attrib` to grant themselves full control over system directories, deny access to defenders/security tools, remove audit trails, or hide malicious binaries under system and hidden attributes.
* Log Source Requirements: Endpoint logs capturing process creation and command-line execution (specifically Windows CLI utilities modifying DACLs or attributes).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) captures when utilities like `icacls.exe`, `cacls.exe`, `takeown.exe`, or `attrib.exe` are spawned, including their command-line arguments.
* NIDS (Suricata + Zeek): NO. DACL and attribute modifications are local system/operating system tasks. They generate no network traffic.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.

## Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'script_block_text contains Set-Acl' — every other condition holds, so the stage gate rejects the events |
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
