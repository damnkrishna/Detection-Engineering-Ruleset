### Technique Breakdown

* What it is: Command and Scripting Interpreter: Python. Adversaries may abuse Python commands and scripts for execution. Python is a powerful interpreter often installed by default on Linux/macOS and frequently deployed in enterprise Windows environments. Attackers can execute malicious scripts directly from memory, spawn shells, or use Python for lateral movement and data exfiltration.
* Log Source Requirements: Process creation logs (Sysmon Event ID 1 / Windows Security Event ID 4688) containing full command-line arguments and parent process lineage.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures executions of `python.exe` or `py.exe`, including the script paths and anomalous parent processes (e.g., Office applications).
    * NIDS (Suricata + Zeek): NO. Python execution is a local host activity, though subsequent network behavior (e.g., outbound C2 over raw sockets) might be detected.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
