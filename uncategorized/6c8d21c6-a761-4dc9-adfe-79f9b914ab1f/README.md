### Technique Breakdown
* What it is: Modify Authentication Process: Password Filter DLL. Password filters are DLLs loaded by LSASS during boot or password changes. Adversaries register custom password filter DLLs to harvest plain-text credentials as users change their passwords.
* Log Source Requirements: Sysmon Registry Set events (Event ID 13) and Sysmon File Creation events (Event ID 11).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Sysmon provides full coverage of LSASS Notification Package registry modifications and DLL files written to system directories.
  - NIDS (Suricata + Zeek): NO. Host-local system manipulation.
* Log Sources Covered:
  - Sysmon Event ID 13 (registry_set)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
