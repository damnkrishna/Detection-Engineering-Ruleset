### Technique Breakdown: T1105

* What it is: Ingress Tool Transfer. Adversaries transfer files (tools, exploits, payloads, or scripts) from external systems into a compromised corporate host. They abuse native Windows utilities (LOLBins) like certutil.exe, bitsadmin.exe, curl.exe, or scripting environments like PowerShell to connect to their external infrastructure and download malicious files onto the filesystem.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688), PowerShell Script Block Logs (Event ID 4104), and Network Connection logs (Sysmon Event ID 3).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 captures command lines. Event ID 4104 captures PowerShell scripts. Event ID 3 captures network activity.
    * Windows Security Logs: PARTIAL. Security logs EID 4688 captures command lines if enabled.
* Log Sources Covered:
    - Sysmon Event ID 1 (process_creation)
    - PowerShell Event ID 4104 (ps_script)
    - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
    - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
