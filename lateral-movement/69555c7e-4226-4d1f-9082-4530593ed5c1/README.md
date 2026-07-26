### Technique Breakdown

* What it is: Remote Services: Distributed COM. Adversaries use Distributed Component Object Model (DCOM) interfaces (such as MMC20.Application, ShellWindows, or ShellBrowserWindow COM objects) to execute arbitrary commands remotely on targets. When accessed, the system DCOM service host (svchost.exe launching DcomLaunch) spawns the corresponding DCOM server host process (like mmc.exe, explorer.exe, or dllhost.exe), which in turn executes the attacker's command by spawning a shell interpreter (cmd.exe or powershell.exe). This distinctive parent-child-grandchild pattern is highly indicative of DCOM abuse.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) capturing process command line and parent/grandparent relationships.
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs the parent process of a newly spawned shell. If the parent is mmc.exe or explorer.exe and its parent is svchost.exe, this chain represents DCOM execution.
  * NIDS (Suricata + Zeek): YES. Network logs capture RPC/DCOM bind requests targeting remote endpoints, but host logs are required to confirm successful command launch.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Distributed COM remote executions and configuration changes can be detected using process creation and registry logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
