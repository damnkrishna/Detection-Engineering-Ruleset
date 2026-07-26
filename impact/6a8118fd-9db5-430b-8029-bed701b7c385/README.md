### Technique Breakdown

* What it is: Data Manipulation. Adversaries modify structured data (such as SQL databases, SQLite files, audit logs, or financial logs) to cause operational disruption, alter transaction details, or conceal evidence of their activity. Detections monitor local file modification events targeting database formats (.db, .sqlite, .mdf) or audit logs (.evtx) by non-standard command shells or scripting engines, as well as process creation command lines invoking database utilities or event log wiping tools.
* Log Source Requirements: Endpoint logs capturing file creation, modification, or write events (Sysmon Event ID 11 / Windows Security Event ID 4663) and process creation logs (Sysmon Event ID 1 / Windows Security Event ID 4688).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 11 logs file path names, extensions, and writing processes. Sysmon Event ID 1 captures database or log management CLI command execution.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 11 (file_event)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Database or log file modification activity can be detected using file event and process creation logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
