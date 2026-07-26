### Technique Breakdown

* What it is: Deobfuscate/Decode Files or Information. Adversaries may use obfuscated files or information to hide artifacts of an intrusion, and may need to decode/deobfuscate them before execution. Common tools include certutil, expand, and copy /b.
* Log Source Requirements: Sysmon Process Creation (Event ID 1) / Windows Event ID 4688.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Process command lines for decode operations are captured.
  - NIDS (Suricata + Zeek): NO. Host-local file operation.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
