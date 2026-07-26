### Technique Breakdown

* What it is: Domain or Tenant Policy Modification. Adversaries modify domain or tenant policies to establish persistence, elevate privileges, or facilitate lateral movement. In Active Directory, this includes modifying GPOs, altering domain trust relationships (to allow access from external malicious domains), or changing directory service object permissions (to grant replication/delegation rights). Adversaries use CLI tools like `netdom.exe`, `nltest.exe`, or PowerShell AD modules to make these modifications.
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters (specifically targeting administrative Active Directory and trust management utilities).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs the execution of utilities like `netdom.exe`, `nltest.exe`, or PowerShell Active Directory cmdlets.
* NIDS (Suricata + Zeek): NO. Trust and policy modifications are local configurations or RPC-based changes. Network logs can capture the replication or RPC calls (like `DRSUAPI`), but do not parse them as policy modification events.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
