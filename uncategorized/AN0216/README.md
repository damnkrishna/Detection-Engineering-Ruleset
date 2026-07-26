### Technique Breakdown: T1563

* What it is: Remote Service Session Hijacking. Adversaries may hijack an existing session of a remote service (such as RDP or ssh) to move laterally and bypass multi-factor authentication or credentials requirements. On Windows, RDP session shadowing (mstsc.exe /shadow) or session redirection (tscon.exe) allows administrators or attackers to hijack or observe user sessions. Before hijacking, adversaries typically run query utilities (like query.exe user or qwinsta.exe) to list active terminal sessions and discover session IDs.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs process paths (mstsc.exe, tscon.exe, query.exe, qwinsta.exe) and command line parameters.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Windows System Log Event ID 7045 (system)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Remote service session hijacking and query tool executions can be detected via Sysmon process creation and Windows Security logs.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
