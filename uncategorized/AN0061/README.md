### Technique Breakdown: T1489

* What it is: Service Stop. Adversaries stop or disable critical endpoint services (such as antivirus programs, firewalls, database servers, or mail transfer agents) to impair system defenses or disrupt business-critical applications (preceding encryption or data destruction). They execute service stops using Windows CLI commands (sc.exe stop, net.exe stop) or PowerShell commands (Stop-Service).
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters (Sysmon Event ID 1 / Windows Security Event ID 4688) and PowerShell script block logs (Sysmon Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 logs the execution of utilities modifying service states. Sysmon Event ID 4104 (Script Block) logs PowerShell scripts stopping services.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Stopping critical services can be detected using process creation and PowerShell script block logs.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
