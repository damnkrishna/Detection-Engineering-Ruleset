### Technique Breakdown

* What it is: Steal or Forge Kerberos Tickets: Golden Ticket. If an adversary compromises your Domain Controller and extracts the KRBTGT account password hash, they can use it to cryptographically forge their own Kerberos Ticket-Granting Tickets (TGTs). This "Golden Ticket" grants them unfettered, persistent administrative access to virtually any resource in the Active Directory domain, even if the user account they are impersonating has its password changed.
* Log Source Requirements: Detecting the creation of the ticket requires endpoint process/command-line monitoring (Sysmon Event ID 1) and PowerShell script block logging (Sysmon Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 (Process Creation) can detect the command-line execution of popular forging tools like Mimikatz or Rubeus on compromised endpoints. Sysmon Event ID 4104 (Script Block) is effective at catching script-based forging.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Golden Ticket forging tool execution on local endpoints can be detected using process creation and PowerShell script block logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
