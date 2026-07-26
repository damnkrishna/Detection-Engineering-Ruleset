### Technique Breakdown

* What it is: Data from Network Shared Drive. Adversaries search and collect sensitive files (like spreadsheets, text documents, or databases) stored on remote network shared drives rather than on the local host. They copy these remote files to a local directory or local staging area prior to exfiltration. Detection focuses on identifying copy utilities (like `xcopy.exe`, `robocopy.exe`, `copy`) or compression tools executing commands targeting remote UNC paths.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) capturing copy utility command parameters.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures command-line parameters, letting security tools look for copy tools referencing network UNC paths (`\\`).
    * NIDS (Suricata + Zeek): YES. Network logs capture SMB file read queries, but host logs confirm the local copy/destination.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
