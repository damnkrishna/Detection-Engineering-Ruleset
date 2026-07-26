### Technique Breakdown

* What it is: Forge Web Credentials: SAML Tokens (widely known as a Golden SAML attack). Adversaries who compromise an Identity Provider (IdP) like Active Directory Federation Services (AD FS) steal the token-signing certificate and the Distributed Key Manager (DKM) key. With these secrets, they can offline-forge perfectly valid SAML tokens. This allows them to bypass multi-factor authentication (MFA) and access federated cloud services (like Microsoft 365 or AWS) as any user in the domain.
* Log Source Requirements: Endpoint process execution, WMI querying, or file access monitoring on the AD FS server, and PowerShell script block logging (Sysmon Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 (Process Creation) can catch the attacker executing tools on the AD FS server to extract the certificates and keys from the Windows Internal Database (WID) or via PowerShell. Sysmon Event ID 4104 (Script Block) is effective at catching script-based queries.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: AD FS SAML certificate extraction attempts on local endpoints can be detected using process creation and PowerShell script block logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
