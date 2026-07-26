### Technique Breakdown
* What it is: Modify Authentication Process: Network Provider DLL. Adversaries register malicious Network Provider DLLs in the registry (e.g., NPFS/RDP providers) to harvest plain-text credentials during user logons. When a user logs in, MPR (Multiple Provider Router) queries all registered network providers, loading their corresponding DLLs and passing the credentials to them.
* Log Source Requirements: Sysmon Registry Set events (Event ID 13) and Sysmon File Creation events (Event ID 11).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Sysmon tracks registry path setting and order changes for Network Providers and file events in System32.
  - NIDS (Suricata + Zeek): NO. Host-local configuration changes.
* Log Sources Covered:
  - Sysmon Event ID 13 (registry_set)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
