### Technique Breakdown

* What it is: Supply Chain Compromise: Compromise Software Supply Chain. Adversaries compromise legitimate software installers or update mechanisms (e.g., utility software updates, driver installers) to deliver malware. When the compromised installer runs, it executes post-installation scripts or helper binaries that spawn command shells or scripting tools to download and install implants, often executing out of temporary directories.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) and Sysmon file creation logs (Event ID 11).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 tracks system installers (such as `msiexec.exe`) or update processes (e.g., `update.exe`, `setup.exe`) spawning child commands. Sysmon Event ID 11 captures file writes by installers to system or startup folders.
  * NIDS (Suricata + Zeek): PARTIAL. Network tools can flag update downloads originating from compromised hosts or non-SSL HTTP channels, but cannot see what processes the updater launches on the system.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Software supply chain installer compromise can be detected using process creation and file creation logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
