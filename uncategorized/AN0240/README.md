### Technique Breakdown: T1518.002

* What it is: Backup Software Discovery. Adversaries enumerate backup solutions installed on a host or domain to identify and subsequently disable or destroy backup data before launching ransomware or destructive attacks. Knowing which backup products are deployed (e.g. Veeam, Acronis, Windows Server Backup, ShadowProtect, CrashPlan) allows adversaries to target their specific service names, processes, or registry entries. Common enumeration methods include querying services (sc.exe query, tasklist.exe /SVC), registry (reg.exe query), or PowerShell WMI queries for known backup product names.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688), PowerShell Script Block Logs (Event ID 4104), and Registry Set Events (Sysmon Event ID 13).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 captures execution of sc.exe, reg.exe, wmic.exe, and PowerShell. Event ID 4104 logs script block details. Event ID 13 logs registry modifications.
    * Windows Security Logs: PARTIAL. Security logs EID 4688 captures command lines if enabled.
* Log Sources Covered:
    - Sysmon Event ID 1 (process_creation)
    - PowerShell Event ID 4104 (ps_script)
    - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
    - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
