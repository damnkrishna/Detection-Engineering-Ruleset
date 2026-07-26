### Technique Breakdown

* What it is: Local Data Staging. Adversaries collect and consolidate sensitive files — documents, credentials, configuration files — into a single local staging directory before exfiltration. Unlike general data staging (T1074), this sub-technique focuses specifically on local host staging: reading files from multiple source locations (Documents, Desktop, network drives) and writing them to a common staging folder (e.g., %TEMP%, C:\Windows\Temp, %USERPROFILE%\AppData\Local).
* Log Source Requirements: Endpoint logs capturing process creation events and file creation events.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs bulk file copy commands. Sysmon Event ID 11 (File Event) captures file creation events within staging paths.
  - NIDS (Suricata + Zeek): NO. Staging is a host filesystem operation.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
