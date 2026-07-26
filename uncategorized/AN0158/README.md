### Technique Breakdown: T1102.001

* What it is: Web Service: Dead Drop Resolver. Adversaries host C2 endpoint IP addresses or connection configurations on high-reputation, legitimate web services (such as GitHub, Pastebin, Reddit, or Twitter). Malicious scripts or binaries execute on the target host and connect to these services to resolve and fetch the secondary C2 IP. Because these web services are trusted by IT departments, network connections to these domains are rarely inspected or blocked.
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
