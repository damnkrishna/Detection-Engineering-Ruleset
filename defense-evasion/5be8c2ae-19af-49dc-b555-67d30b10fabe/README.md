# 5be8c2ae-19af-49dc-b555-67d30b10fabe — golden replay datasets

`Group Policy Modification via Script Block (AN0854-B)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1484.001

* What it is: Group Policy Modification. Adversaries modify Group Policy Objects (GPOs) to deploy malware, establish persistence, disable security settings, or escalate privileges across an Active Directory domain. By modifying GPO files within the domain's SYSVOL share, they can execute code on domain-joined systems.
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters from domain administrative utilities and scripting engines (like PowerShell, secedit.exe, or lgpo.exe).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs the execution of CLI tools like secedit.exe, lgpo.exe, or PowerShell containing GPO cmdlets.
  * NIDS (Suricata + Zeek): NO. GPO templates are loaded over SMB, but network logs cannot reliably inspect the contents of encrypted SMB traffic.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
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
| `benign_1.jsonl` | 0 | near-miss value for 'script_block_text contains New-GPO' — every other condition holds, so the stage gate rejects the events |
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
