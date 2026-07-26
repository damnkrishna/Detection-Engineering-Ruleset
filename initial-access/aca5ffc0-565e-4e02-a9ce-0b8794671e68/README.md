### Technique Breakdown

* What it is: Phishing. Adversaries send malicious attachments or links through email (e.g., via Outlook) or messaging tools to gain initial access to target environments. When the user opens the attachment, it spawns script interpreters (like PowerShell, cmd, or mshta) or launching programs to run external code.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) capturing parent-child process execution patterns, and Sysmon file creation logs (Event ID 11).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures email clients spawning scripting tools or office productivity suites. Sysmon Event ID 11 captures files written by mail clients.
  * NIDS (Suricata + Zeek): YES. Network logs can flag SMTP/IMAP attachments with suspicious extensions or connections to known phishing domains.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Phishing activity can be detected using process creation and file creation logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
