### Technique Breakdown

* What it is: Account Access Removal. Adversaries delete or disable local or domain user accounts (particularly administrator accounts) to lock out legitimate system administrators, prevent incident response recovery, or disrupt business operations. They execute account deactivations or deletions using command-line administrative tools (net.exe user <username> /delete or /active:no) or PowerShell cmdlets (Remove-LocalUser, Disable-LocalUser).
* Log Source Requirements: Endpoint logs capturing process creation and command line arguments (Sysmon Event ID 1 / Windows Security Event ID 4688) and PowerShell script block logs (Sysmon Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 logs CLI command parameters for user configuration utilities. Sysmon Event ID 4104 (Script Block) logs PowerShell script-based user management actions.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: User account access removal activity can be detected using process creation and PowerShell script block logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
