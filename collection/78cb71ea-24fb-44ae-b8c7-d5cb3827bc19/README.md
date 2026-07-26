### Technique Breakdown

* What it is: Databases. Adversaries target database systems to collect sensitive information stored in structured data stores — such as customer records, financial data, credentials, or intellectual property. On Windows, they use database client tools (sqlcmd.exe, isql.exe, osql.exe, bcp.exe, mysql.exe) to query databases and export results, often initiated from unexpected parent processes like cmd.exe, powershell.exe, or explorer.exe. The exported data is typically written to .csv, .sql, or .bak dump files in user temp directories.
* Log Source Requirements: Endpoint logs capturing process creation events and network connection events.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs database client tool execution. Sysmon Event ID 3 (Network Connection) logs database connection attempts.
  - NIDS (Suricata + Zeek): YES. Database connections to local or remote servers can be identified.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
