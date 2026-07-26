### Technique Breakdown

* What it is: Exploitation for Client Execution. Adversaries exploit software vulnerabilities in client applications (e.g., web browsers, Microsoft Office, PDF readers, Flash players) to execute arbitrary code. A successful exploit often results in the compromised application crashing unexpectedly or spawning an unusual child process (like `cmd.exe` or `powershell.exe`) and writing payloads to disk.
* Log Source Requirements: Process creation logs (Sysmon Event ID 1), Application crash logs (Windows Application Event ID 1000), File Creation logs (Sysmon Event ID 11), and Network logs (Sysmon Event ID 3).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Correlates the crash, the child process spawned by the exploited app, and the file drop.
    * NIDS (Suricata + Zeek): PARTIAL. Network sensors might detect the exploitation attempt (e.g., malicious PDF signature) or the subsequent C2 callback.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
