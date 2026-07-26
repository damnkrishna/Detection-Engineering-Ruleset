### Technique Breakdown

* What it is: Data Staged. Adversaries aggregate and stage collected data in a central location before exfiltration, often to simplify transfer and avoid repeated connections to the target system. On Windows, this typically involves copying or moving sensitive files (documents, databases, credential stores) into a temporary staging directory, then compressing or archiving them using 7z.exe, WinRAR.exe, or built-in Compress-Archive (PowerShell) before sending them out. The staging location is frequently C:\Windows\Temp, %APPDATA%, or a custom subdirectory under C:\Users\Public.
* Log Source Requirements: Endpoint logs capturing process creation events and file creation events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs when compression utilities run targeting temp folders, and Event ID 11 (File Event) logs when staged archive files are written.
* NIDS (Suricata + Zeek): NO. Offline, local host actions.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
