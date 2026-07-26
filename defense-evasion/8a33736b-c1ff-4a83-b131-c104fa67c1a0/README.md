### Technique Breakdown

* What it is: Valid Accounts: Domain Accounts. Adversaries compromise domain accounts (specifically Domain Administrators) to move laterally across an Active Directory environment, execute remote commands, and access sensitive resources. Under standard security best practices, Domain Administrator accounts should only log onto Domain Controllers or secure administrative jump boxes. A Domain Admin logging onto standard workstations or member servers suggests lateral movement.
* Log Source Requirements: Windows Security Event Log capturing authentication events, and network connection logs tracking access to authentication services.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Windows Security Event ID 4624 tracks domain account logon attempts on endpoints. Sysmon Event ID 3 tracks network connection activity.
  - NIDS (Suricata + Zeek): YES (Partial). Network monitoring can capture Kerberos ticket requests or SMB handshakes.
* Log Sources Covered:
  - Security Event ID 4624 (security)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
