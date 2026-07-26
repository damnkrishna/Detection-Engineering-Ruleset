### Technique Breakdown
* What it is: Modify Authentication Process: Domain Controller Authentication. Adversaries patch domain controller authentication processes (specifically LSASS) to inject a "Skeleton Key," allowing them to authenticate as any user using a master password while legitimate authentication processes continue working normally.
* Log Source Requirements: Sysmon Process Access logs (Event ID 10), Sysmon Image Load logs (Event ID 7), and Sysmon Registry Set logs (Event ID 13).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Sysmon provides visibility into LSASS memory access, image loads, and registry changes on Domain Controllers.
  - NIDS (Suricata + Zeek): NO. Host-local system manipulation.
* Log Sources Covered:
  - Sysmon Event ID 10 (process_access)
  - Sysmon Event ID 7 (image_load)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
