### Technique Breakdown

* What it is: Remote Services: SMB/Windows Admin Shares. Adversaries abuse default Windows administrative shares (like `C$`, `ADMIN$`, or `IPC$`) to copy malware files remotely to target hosts and execute them. A classic lateral movement tool that does this is PsExec (or equivalent Impacket scripts like `psexec.py`). When PsExec runs, it copies a service binary (e.g. `PSEXESVC.exe`) to the remote host's administrative share (`ADMIN$`, which is `C:\Windows\`) and uses the Service Control Manager (`services.exe`) to register and start it. The signature endpoint behavior is `services.exe` spawning a non-standard child process representing the PsExec agent.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) auditing system services.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs the parent process of newly started services. If `services.exe` spawns an executable from the Windows folder that is not a standard service binary, it is a high-confidence alert.
    * NIDS (Suricata + Zeek): YES. Network filters capture SMB access to administrative shares (ports 139, 445), but endpoint logs are critical to identify the resulting code execution.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Windows System Log Event ID 7045 (system)
* Log Sources Missing / Unused:
  - None.
* Conclusion: SMB admin share executions can be detected using process creation and system installation logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
