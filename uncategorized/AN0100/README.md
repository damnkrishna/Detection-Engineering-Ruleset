### Technique Breakdown: T1102.002

* What it is: Web Service: Bidirectional Communication. Adversaries leverage legitimate web services (such as Slack, Telegram, Discord, Dropbox, or Box APIs) as bidirectional Command and Control channels. They pull commands from the API (GET requests) and upload stolen data or command output (POST requests). Because these services are TLS-encrypted and trusted by organizations, this C2 channel successfully evades basic network boundary restrictions.
* Log Source Requirements: Endpoint network connection logs (Sysmon Event ID 3) and PowerShell Script Block Logs (Event ID 4104).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 3 captures network activity. Event ID 4104 captures PowerShell scripts.
    * Windows Security Logs: NO. Local network activity and script content is primarily captured by Sysmon.
* Log Sources Covered:
    - Sysmon Event ID 3 (network_connection)
    - PowerShell Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
    - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
