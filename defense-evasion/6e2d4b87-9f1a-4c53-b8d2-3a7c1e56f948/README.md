### Technique Breakdown

* What it is: Obfuscated Files or Information. Adversaries may attempt to make an executable or file difficult to discover or analyze by encoding, encrypting, or otherwise obfuscating its contents — most commonly via PowerShell Base64 encoded commands.
* Log Source Requirements: Sysmon Process Creation (Event ID 1) / Windows Event ID 4688.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. PowerShell -EncodedCommand and similar flags are captured.
  - NIDS (Suricata + Zeek): NO. Host-local obfuscation.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
