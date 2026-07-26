### Technique Breakdown

* What it is: Remote Access Software. Adversaries deploy or use legitimate remote monitoring and management (RMM) software (such as TeamViewer, AnyDesk, ScreenConnect, LogMeIn, Splashtop) to establish interactive command-line and desktop control over compromised hosts. Because these tools are commercial software and use standard HTTPS/TLS (port 443) outbound connections, they bypass network firewalls and do not trigger traditional antivirus alerts.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) and Network Connection logs (Sysmon Event ID 3).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 logs the execution of RMM client files. Sysmon Event ID 3 captures outbound socket connections to remote control servers.
    * Windows Security Logs: PARTIAL. Security logs EID 4688 captures command lines if enabled.
* Log Sources Covered:
    - Sysmon Event ID 1 (process_creation)
    - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
    - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
