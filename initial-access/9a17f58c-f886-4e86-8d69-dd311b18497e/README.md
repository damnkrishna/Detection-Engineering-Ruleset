### Technique Breakdown

* What it is: Drive-by Compromise. Adversaries gain initial access by exploiting a user's web browser when they visit a compromised or malicious website. Successful browser exploitation is identified by the browser process (e.g., Chrome, Edge, Firefox) directly spawning shell interpreters, scripting hosts, binary loaders, or downloading and launching payloads from temporary user directories.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) capturing parent-child process relationships, and PowerShell script block logs (Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures browser processes spawning shell/script hosts. Sysmon Event ID 4104 (Script Block) is effective at catching scripting activity containing browser context references.
  * NIDS (Suricata + Zeek): YES. Network monitoring can identify downloads of binary payloads with anomalous headers or from high-risk domains, but host-based process monitoring is needed to verify execution.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Drive-by compromise execution can be detected using process creation and PowerShell script block logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
