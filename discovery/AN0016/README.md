### Technique Breakdown

* What it is: Domain Trust Discovery. Adversaries enumerate domain trust relationships to identify forest or domain boundaries they can pivot across. By discovering which domains trust each other (and the direction of that trust), adversaries identify targets for Kerberoasting, cross-domain lateral movement, or privilege escalation to forest root domains. Common enumeration methods include `nltest.exe /domain_trusts`, PowerShell Active Directory cmdlets (`Get-ADTrust`), or native Win32 API functions (`DsEnumerateDomainTrusts`, `NetEnumerateTrustedDomains`).
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) and PowerShell Script Block Logs (Event ID 4104).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures execution of `nltest.exe` and PowerShell AD cmdlets. Event ID 4104 logs the script block contents.
    * NIDS (Suricata + Zeek): NO. Domain trust enumeration is a host-local operation.
* Log Sources Covered:
    - Sysmon Event ID 1 (process_creation)
    - PowerShell Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
    - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
