### Technique Breakdown

* What it is: Email Collection: Remote Email Collection. Adversaries target and collect emails from remote mail servers (such as Microsoft Exchange or Office 365) using compromised credentials. They access mail databases programmatically via Exchange Web Services (EWS) API, MAPI, or PowerShell command blocks (using Exchange cmdlets like `Export-Mailbox` or EWS managed APIs). Host-based detection checks for unexpected processes (like scripting engines) loading mail API assemblies or executing exchange query cmdlets.
* Log Source Requirements: Windows Security Event Log Event ID 4624 (Logon) or Sysmon process creation logs (Event ID 1) combined with PowerShell script block logs (Event ID 4104).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs process details, and PowerShell logging captures the script blocks compiling mail retrieval commands.
    * NIDS (Suricata + Zeek): YES. Network filters capture SSL connections to remote mail servers (e.g. `outlook.office365.com`), but cannot easily decode HTTPS encrypted API payloads.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
