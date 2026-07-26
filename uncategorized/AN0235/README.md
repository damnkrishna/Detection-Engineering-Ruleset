### Technique Breakdown: T1003.002

* What it is: OS Credential Dumping: Security Account Manager (SAM). Adversaries target the SAM database on Windows to extract local account credentials (NTLM hashes). This allows them to crack passwords offline or use the hashes directly for pass-the-hash attacks. The most common method is exporting the SAM, SYSTEM, and SECURITY registry hives using built-in tools like reg.exe.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) tracking execution, registry write logs (Sysmon Event ID 13), and file system logs (Sysmon Event ID 11) tracking file creation.
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 (Process Creation) captures reg.exe execution. Event ID 13 (Registry Set) captures modification to registry hives. Event ID 11 (File Event) captures raw registry hive dumps written to disk.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.
* Conclusion: SAM registry hive export attempts can be detected using process creation, registry modification, and file event logs.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
