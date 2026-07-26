### Technique Breakdown: T1485

* What it is: Data Destruction. Adversaries permanently delete or overwrite sensitive files, directories, or backups on host machines to cause operational disruption or to cover evidence of intrusion. To ensure files cannot be recovered, they employ file wiping utilities (such as sdelete.exe or cipher.exe /w) or delete Windows Volume Shadow Copies (vssadmin.exe delete shadows, wmic shadowcopy delete) to remove local system backup states. They may also use PowerShell script commands targeting shadow copy management namespaces.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) tracking execution, and PowerShell script block logs (Sysmon Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 logs parent processes, target processes, and command line parameters for shadow copy management or wiper tools. Sysmon Event ID 4104 (Script Block) captures script-based shadow copy deletions.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: File wiping and volume shadow copy deletion activity can be detected using process creation and PowerShell script block logs.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
