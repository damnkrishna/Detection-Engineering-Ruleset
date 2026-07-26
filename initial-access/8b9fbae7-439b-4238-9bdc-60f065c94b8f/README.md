### Technique Breakdown

* What it is: External Remote Services. Adversaries leverage external-facing remote access solutions (such as virtual private networks (VPNs) or remote desktop protocols (RDP)) to gain initial access to the internal network. Once they authenticate using compromised credentials, they immediately initiate host reconnaissance by spawning built-in system administration utilities (`whoami.exe`, `net.exe`, `ipconfig.exe`, `nltest.exe`) from the remote session shell.
* Log Source Requirements: Windows Security Event Log Event ID 4624 (Logon) and Sysmon process creation logs (Event ID 1).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Windows Security log captures remote RDP connections (Logon Type 10) and network logins (Logon Type 3) along with the source IP address. Sysmon Event ID 1 captures the user session initiating system discovery commands.
  * NIDS (Suricata + Zeek): YES. Network logs track RDP and VPN connections to gateways, but host logs are needed to correlate the logon with subsequent shell actions.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Windows Security Event ID 4624 (authentication)
* Log Sources Missing / Unused:
  - None.
* Conclusion: External remote services authentication and follow-on execution can be detected using process creation and security logon logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
