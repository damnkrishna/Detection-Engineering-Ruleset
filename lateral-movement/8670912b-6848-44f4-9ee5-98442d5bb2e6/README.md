### Technique Breakdown

* What it is: Software Deployment Tools. Adversaries abuse third-party or native enterprise software deployment agents (such as Microsoft Endpoint Configuration Manager/SCCM CcmExec.exe, PDQ Deploy, Altiris, or Group Policy installation wrappers) to run administrative tasks or deploy malware laterally across a network of systems. Detection focuses on identifying deployment agent parent processes launching interactive shells (cmd.exe, powershell.exe) or network utility tools with high privileges.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) capturing parent-child process execution contexts.
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 provides detailed parent process path information, letting defenders look for SCCM or PDQ binaries spawning shells.
  * NIDS (Suricata + Zeek): PARTIAL. Network tools can track deployment protocol queries, but cannot verify the specific local process lineage on endpoints.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - PowerShell Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Abuse of software deployment tools can be detected using process creation and PowerShell logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
