### Technique Breakdown

* What it is: Steal or Forge Kerberos Tickets: AS-REP Roasting. Adversaries hunt for Active Directory user accounts that have the "Do not require Kerberos preauthentication" flag enabled. If this flag is set, anyone can request an Authentication Service (AS) ticket for that user. The Domain Controller will respond with an AS-REP message that contains a chunk of data encrypted with the user's password hash. The attacker saves this data and cracks it offline.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) tracking execution, and PowerShell script block logs (Sysmon Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 (Process Creation) is great for catching the command-line execution of tools like Rubeus, PowerView, or Impacket. Sysmon Event ID 4104 (Script Block) captures scripts performing these operations in memory.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: AS-REP roasting tool execution on local endpoints can be detected using process creation and PowerShell script block logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
