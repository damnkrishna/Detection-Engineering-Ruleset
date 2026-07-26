### Technique Breakdown

* What it is: Data from Information Repositories. Adversaries target and collect data from information repositories (like SharePoint, Confluence, internal wikis, or database repositories) to harvest intellectual property, credentials, or network diagrams. They may programmatically download directories or query tables using command-line tools (e.g. `sqlcmd.exe`), PowerShell scripts containing SharePoint client APIs (such as `Microsoft.SharePoint.Client`), or command-line web clients (e.g. `curl.exe`, `wget.exe`, `Invoke-WebRequest`).
* Log Source Requirements: Windows Security Event Log Event ID 4688 or Sysmon process creation logs (Event ID 1) capturing command-line parameters of database or repository query tools.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs process details, capturing cmdline parameters that query or download from internal information systems.
    * NIDS (Suricata + Zeek): YES. Network filters capture high-volume HTTP/HTTPS requests to internal wikis or database ports (1433, 1521, 3306), indicating mass enumeration.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
