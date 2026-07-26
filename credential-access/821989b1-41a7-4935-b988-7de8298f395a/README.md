### Technique Breakdown

* What it is: Credentials from Password Stores: Windows Credential Manager. Adversaries attempt to extract passwords and credential materials stored securely in the Windows Credential Manager (the "Vault"). This vault often contains saved RDP credentials, network share passwords, and web credentials. Attackers typically use native "Living off the Land" (LotL) binaries like cmdkey.exe or vaultcmd.exe to enumerate and dump these.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) tracking execution, and PowerShell script block logs (Sysmon Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 (Process Creation) is perfectly suited to catch the execution of cmdkey.exe or vaultcmd.exe when paired with enumeration flags. Sysmon Event ID 4104 (Script Block) is effective at catching script-based queries.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Windows Credential Manager access using command line utilities and PowerShell script blocks can be detected using process creation and script block logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
