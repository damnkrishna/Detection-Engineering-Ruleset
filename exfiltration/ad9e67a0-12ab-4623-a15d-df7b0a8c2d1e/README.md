### Technique Breakdown

* What it is: Scheduled Transfer. Adversaries schedule data exfiltration to align with normal business hours or system maintenance windows, making their transfers less noticeable. This is typically implemented via Windows Scheduled Tasks executing script blocks or command utilities (such as curl.exe, powershell.exe) that initiate file transfers to remote destinations. Detections monitor scheduled processes executing transfer cmdlets/arguments, or scheduled task XML files written to the Tasks directory.
* Log Source Requirements: Endpoint logs capturing process creation events and file creation events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs process spawning by the Task Scheduler engine with transfer arguments, and Event ID 11 (File Event) logs task definition XML file writes under System32\Tasks.
* NIDS (Suricata + Zeek): YES (Partial). Outbound network traffic can indicate periodic beaconing.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
