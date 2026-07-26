### Technique Breakdown

* What it is: Spearphishing via Service. Adversaries deliver spearphishing payloads or links via third-party web services (e.g., personal webmail like Gmail/Outlook, social media like LinkedIn/Twitter, or messaging platforms like Discord, Slack, Telegram, and Teams) rather than traditional enterprise email. This sub-technique bypasses enterprise email gateway controls. The detection focuses on identifying suspicious activity originating from web browser processes or chat/messaging applications, such as downloading and executing scripting interpreters, shells, or anomalous binaries.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) and PowerShell script block logs (Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures command-line execution and parent-child process relationships. Event ID 4104 (Script Block) captures PowerShell scripts running from downloads or temp paths.
  * NIDS (Suricata + Zeek): PARTIAL. Network monitoring can identify connections to known messaging API endpoints, but SSL/TLS encryption prevents payload inspection, making host-based endpoint logs essential.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Spearphishing via third-party services can be detected using process creation and PowerShell script block logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
