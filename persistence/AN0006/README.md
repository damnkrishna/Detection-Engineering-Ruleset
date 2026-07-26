### Technique Breakdown

* What it is: Domain Account Creation. Adversaries create new domain user accounts to establish persistent access to compromised environments. Unlike local accounts, domain accounts provide access across all domain-joined systems. On Windows, this is typically performed via net.exe user /add /domain, PowerShell Active Directory cmdlets (New-ADUser), or LDAP writes to Active Directory.
* Log Source Requirements: Endpoint logs capturing process creation events and system events (specifically Windows Security Log Event ID 4720).
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures net.exe and PowerShell AD cmdlets. Windows Security Event ID 4720 captures user account creation on Domain Controllers.
  - NIDS (Suricata + Zeek): NO. Focuses on local AD log sources.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Security Event ID 4720 (security)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
