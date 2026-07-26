### Technique Breakdown

* What it is: Security Software Discovery. Adversaries enumerate installed or running security products — such as antivirus engines, endpoint detection & response (EDR) agents, host-based firewalls, or SIEM agents — to understand what defenses are in place. This shapes their evasion strategy (e.g. choosing an implant that bypasses the detected AV). Common enumeration approaches include sc.exe query for services, wmic.exe product queries, netsh.exe advfirewall show allprofiles, tasklist.exe /SVC, or PowerShell WMI queries targeting known vendor product names.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688), PowerShell Script Block Logs (Event ID 4104), and Registry Set Events (Sysmon Event ID 13).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 captures execution of sc.exe, netsh.exe, wmic.exe, and PowerShell. Event ID 4104 logs script block details. Event ID 13 logs registry modifications.
    * Windows Security Logs: PARTIAL. Security logs EID 4688 captures command lines if enabled.
* Log Sources Covered:
    - Sysmon Event ID 1 (process_creation)
    - PowerShell Event ID 4104 (ps_script)
    - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
    - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
