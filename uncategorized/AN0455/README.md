### Technique Breakdown: T1201

* What it is: Password Policy Discovery. Adversaries query local or domain password policies to understand account lockout thresholds, minimum password lengths, and complexity requirements. This informs credential attacks — for example, discovering a 10-attempt lockout threshold allows attackers to safely attempt 9 passwords per account without triggering lockouts. Common tools include net.exe accounts, secedit.exe /export, or PowerShell Active Directory cmdlets like Get-ADDefaultDomainPasswordPolicy.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) and PowerShell Script Block Logs (Event ID 4104).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 captures execution of net.exe, secedit.exe, and PowerShell along with their command-line arguments. Event ID 4104 logs script block details.
    * Windows Security Logs: PARTIAL. Security logs EID 4688 captures command lines if enabled.
* Log Sources Covered:
    - Sysmon Event ID 1 (process_creation)
    - PowerShell Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
    - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
