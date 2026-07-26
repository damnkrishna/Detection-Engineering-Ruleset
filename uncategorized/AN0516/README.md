### Technique Breakdown: T1570

* What it is: Lateral Tool Transfer. Adversaries may transfer tools or other files from one system to another inside a compromised environment (lateral movement). They often copy utilities, scripts, or credential access tools to administrative network shares (such as C$, ADMIN$, IPC$) on a remote machine using built-in command-line copy/move tools (e.g. copy, move, xcopy.exe, robocopy.exe). Once the files are successfully copied, they are executed remotely.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures the creation of command-line processes (cmd.exe, powershell.exe, xcopy.exe, robocopy.exe) and lists their full command arguments, allowing checks for network share formats.
  * NIDS (Suricata + Zeek): NO. While network monitoring can inspect SMB file transfer headers, decoding the command line of the process that initiated the transfer on the source system requires host-level auditing.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Lateral tool transfer can be detected using process creation and file event logs.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
