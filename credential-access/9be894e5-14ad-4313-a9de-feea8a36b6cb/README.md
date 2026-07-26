### Technique Breakdown

* What it is: Brute Force: Password Cracking. This involves adversaries attempting to recover usable, cleartext passwords from stolen cryptographic hashes (like the NTLM hashes they might have grabbed from the SAM dump). While adversaries usually do this offline on their own hardware, they occasionally execute cracking utilities (like Hashcat or John the Ripper) or script-based cracking routines directly onto compromised endpoints.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) tracking execution, and PowerShell script block logs (Sysmon Event ID 4104) tracking script content.
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 (Process Creation) is the primary telemetry source for binary execution. Sysmon Event ID 4104 (Script Block) is effective at catching script-based crackers run entirely in memory.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Password cracking tool execution on local endpoints can be detected using process creation and PowerShell script block logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
