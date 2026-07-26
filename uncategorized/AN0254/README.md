### Technique Breakdown: T1033

* What it is: System Owner/User Discovery. Adversaries enumerate the current user context, logged-on users, or domain accounts to understand who is operating a system, identify high-value targets, or tailor further lateral movement. On Windows, typical methods include whoami.exe, query.exe user, quser.exe, net.exe user, or WMI/PowerShell queries (Get-WmiObject Win32_ComputerSystem, Get-LocalUser, Get-ADUser).
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) and PowerShell Script Block Logs (Event ID 4104).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 captures spawning of whoami.exe, quser.exe, and net.exe. Event ID 4104 logs script block details.
    * Windows Security Logs: PARTIAL. Security logs EID 4688 captures command lines if enabled.
* Log Sources Covered:
    - Sysmon Event ID 1 (process_creation)
    - PowerShell Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
    - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
