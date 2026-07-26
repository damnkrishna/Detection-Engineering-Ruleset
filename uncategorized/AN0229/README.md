### Technique Breakdown: T1491.001

* What it is: Internal Defacement. Adversaries modify the UI displays of internal systems or user endpoints to convey a message (such as ransom instructions, political statements, or compromise alerts). In Windows environments, this includes hijacking the system pre-logon warning message by altering registry values legalnoticecaption and legalnoticetext under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, or modifying the user desktop wallpaper registry keys under HKCU\Control Panel\Desktop\wallpaper.
* Log Source Requirements: Registry modification logs (Sysmon Event ID 13) and host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) tracking execution.
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 13 (Registry Set) is perfectly suited to track direct value modifications to defacement keys. Sysmon Event ID 1 captures command-line registry utilities or powershell cmdlets attempting these modifications.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 13 (registry_set)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Registry-based system defacement modifications can be detected using registry set and process creation logs.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
