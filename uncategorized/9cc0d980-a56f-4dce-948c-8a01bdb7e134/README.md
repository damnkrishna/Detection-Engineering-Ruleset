### Technique Breakdown
* What it is: Modify Authentication Process: Hybrid Identity. Adversaries tamper with hybrid identity services (such as Azure AD Connect or AD FS) to bypass authentication mechanisms or steal credentials. This includes injecting malicious DLLs into hybrid identity sync agent directories or modifying hybrid configuration registries.
* Log Source Requirements: Sysmon Registry Set events (Event ID 13), Sysmon Image Load events (Event ID 7), and Sysmon File Creation events (Event ID 11).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Sysmon provides full coverage of file writes, registry modifications, and DLL loads in hybrid agent processes.
  - NIDS (Suricata + Zeek): NO. Host-local system file/registry modifications.
* Log Sources Covered:
  - Sysmon Event ID 13 (registry_set)
  - Sysmon Event ID 11 (file_event)
  - Sysmon Event ID 7 (image_load)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
