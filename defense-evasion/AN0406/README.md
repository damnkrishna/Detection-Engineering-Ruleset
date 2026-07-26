# AN0406 — golden replay datasets

`Disabling or Tampering with Windows Firewall (AN0406)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1686

* What it is: Disable or Modify System Firewall. Adversaries disable or modify system firewalls to permit network traffic that would otherwise be blocked. They do this to enable command-and-control (C2) communication, permit inbound lateral movement (RDP, WinRM, SMB), or allow file exfiltration. On Windows, this is commonly done by executing commands via `netsh.exe`, PowerShell cmdlets like `Set-NetFirewallProfile`, or stopping the Windows Defender Firewall service (`mpssvc`).
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters (specifically targeting tools that modify firewall profiles or stop the firewall service).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs the execution of utilities like `netsh.exe`, `sc.exe`, or PowerShell commands modifying firewall states.
* NIDS (Suricata + Zeek): NO. Firewall configuration modification is a local host action. It does not produce a distinct network signature (though network tools may capture the resulting unauthorized traffic that is allowed through the firewall).
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

## Blind Spots & Tuning

- Legitimate administrative troubleshooting or network configuration scripts that temporarily disable profiles or remove rules.
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'image_path regex .+\Q\netsh.exe\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'cmd_line contains off' — every other condition holds, so the stage gate rejects the events |

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
