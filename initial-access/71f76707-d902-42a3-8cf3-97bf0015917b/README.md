### Technique Breakdown

* What it is: Valid Accounts. Adversaries hijack legitimate credentials of local, domain, or service accounts to gain initial access, establish persistence, or escalate privileges. Because they utilize valid credentials, their activities appear benign. Detection relies on monitoring anomalous authentication indicators, such as remote logons (Logon Type 3 or 10) by highly privileged accounts executing from unexpected source endpoints.
* Log Source Requirements: Windows Security Event Log capturing authentication events, and network connection logs tracking access to remote systems.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Windows Security Event ID 4624 logs logon events. Sysmon Event ID 3 captures network connections.
  - NIDS (Suricata + Zeek): YES (Partial). Network security tools can log Kerberos or NTLM authentications over protocols like SMB/RDP.
* Log Sources Covered:
  - Security Event ID 4624 (security)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
