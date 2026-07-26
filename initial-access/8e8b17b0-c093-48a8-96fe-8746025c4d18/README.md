### Technique Breakdown

* What it is: Supply Chain Compromise. Adversaries compromise third-party software products or updates prior to installation. Once the user installs the package, the installation process or the initial run of the binary triggers post-compromise actions (such as writing persistence registry keys, dropping payload files to temp directories, or spawning command prompts to fetch C2 implants).
* Log Source Requirements: Sysmon process creation logs (Event ID 1) and PowerShell script block logs (Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 tracks installer processes spawning scripting shells or download tools. Sysmon Event ID 4104 (Script Block) captures scripting activity initiated by installers.
  * NIDS (Suricata + Zeek): PARTIAL. Network tools can spot unusual HTTP payloads during updates, but host audits are necessary to detect the post-install behavior chain.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Supply chain compromise post-installation execution can be detected using process creation and PowerShell script block logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
