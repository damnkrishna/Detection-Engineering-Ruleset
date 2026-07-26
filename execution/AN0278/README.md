# AN0278 — golden replay datasets

`Suspicious Lua Script Execution (AN0278)`

Generated from the live rule on `siem.correlation.rules`. Every event is derived
from this rule's own IR — conditions, aggregate threshold, window and stage
timings — and every dataset was replayed through the production deserializer and
the production-parity rule dispatcher before being written. See `proof.md`.

## Technique Breakdown: T1059.011

* What it is: Lua. Adversaries abuse built-in or dropped Lua interpreters (`lua.exe`, `luac.exe`, `wlua.exe`) to execute Lua scripts (`.lua`). Lua is a lightweight scripting language often embedded in game clients, network software (like Nmap or Wireshark), or security tools. Attackers drop standalone Lua interpreters to execute malicious payload scripts, avoiding detection systems that only monitor PowerShell, VBScript, or command shells.
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters (specifically targeting standalone Lua execution or interpreters spawned by suspicious parent processes).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs the execution of Lua interpreters, including their command-line arguments and parent process names.
* NIDS (Suricata + Zeek): NO. Lua script execution is local. Network logs cannot detect the execution itself (though they might alert on script downloads or C2 network traffic).
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

## Blind Spots & Tuning

- Development environments or legitimate applications utilizing embedded Lua scripting engines (e.g., Nmap scripts, Wireshark plugins).
- Tune with allowlists for known trusted execution paths.

## Files

| File | Expected alerts | Why |
|---|---|---|
| `true_positive_1.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `true_positive_2.jsonl` | 1 | THRESHOLD: stage 0 × 1 event(s) |
| `benign_1.jsonl` | 0 | near-miss value for 'parent_image regex .+\Q\winword.exe\E$' — every other condition holds, so the stage gate rejects the events |
| `benign_2.jsonl` | 0 | near-miss value for 'image_path regex .+\Q\lua.exe\E$' — every other condition holds, so the stage gate rejects the events |

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
