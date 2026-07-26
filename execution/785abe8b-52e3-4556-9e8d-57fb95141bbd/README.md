### Technique Breakdown

* What it is: Trusted Developer Utilities Proxy Execution: ClickOnce. Adversaries abuse the Windows ClickOnce deployment technology (dfshim.dll and dfsvc.exe) or MSBuild compiler utilities to execute malicious applications. Attackers can abuse this by using rundll32.exe to call dfshim.dll with a URL pointing to a malicious ClickOnce application, or by deploying malicious XML project files, bypassing application control rules because these utilities are trusted Microsoft executables.
* Log Source Requirements: Endpoint logs capturing process execution, command line parameters, and file write events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs when rundll32.exe loads dfshim.dll and when dfsvc.exe spawns subprocesses, and Sysmon Event ID 11 (File Event) logs when project or deployment files are written.
* NIDS (Suricata + Zeek): NO. Execution is local.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
