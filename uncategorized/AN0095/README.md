### Technique Breakdown: T1057

* What it is: Process Discovery. Adversaries enumerate running processes on a target host to identify active security tools, running services, or user applications. The information helps adversaries determine if a host is being monitored, which security products are active, or where to inject malicious code. Common enumeration tools include tasklist.exe, wmic.exe process list, or PowerShell's Get-Process cmdlet.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) and PowerShell Script Block Logs (Event ID 4104).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 captures spawning of tasklist.exe, wmic.exe, and PowerShell. Event ID 4104 logs script block details.
    * Windows Security Logs: PARTIAL. Security logs EID 4688 captures command lines if enabled.
* Log Sources Covered:
    - Sysmon Event ID 1 (process_creation)
    - PowerShell Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
    - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
