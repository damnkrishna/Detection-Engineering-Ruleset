### Technique Breakdown

* What it is: Phishing: Spearphishing Link. Adversaries deliver links in phishing emails or chat messages pointing to malicious resources (such as drive-by download sites, credential harvesting landing pages, or directly linking to malicious files hosted on cloud services). When a user clicks the link, the mail client or messaging app spawns the default system web browser with the URL in the command-line arguments.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) capturing parent-child process chains, and PowerShell script block logs (Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures parent process details (e.g., `outlook.exe`, `teams.exe`) spawning browser processes. Sysmon Event ID 4104 (Script Block) captures PowerShell scripts attempting to fetch external resources or parse links.
  * NIDS (Suricata + Zeek): YES. Network monitoring records HTTP GET requests to external hosts, but correlating the web traffic with the local application context requires host-based process data.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Spearphishing link execution can be detected using process creation and PowerShell script block logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
