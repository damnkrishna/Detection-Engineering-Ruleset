### Technique Breakdown

* What it is: Automated Exfiltration. Adversaries automate the search, collection, packaging, and transmission of sensitive files using scheduled scripts or custom implants. Once deployed, these scripts execute at set intervals (using scheduled tasks or system daemons), compress targeted file formats (using LOLBins like tar.exe or makecab.exe), and transmit them to external infrastructure. Detections monitor automated archiving processes or the creation of staged compressed files in public directories.
* Log Source Requirements: Endpoint logs capturing process creation events and file creation events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs archiving command executions spawned by scheduling or scripting interpreters, and Event ID 11 (File Event) logs creation of staged archives.
* NIDS (Suricata + Zeek): YES (Partial). Outbound network logs can reveal periodic beaconing, but host logs are required to detect local staging.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
