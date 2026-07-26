### Technique Breakdown: T1119

* What it is: Automated Collection. Adversaries use scripts or utilities to automatically discover and collect files, clipboard content, or system information at scale. Rather than manually browsing and copying individual files, they run automated commands that recursively search for target file types (e.g., dir /s /b *.docx, Get-ChildItem -Recurse -Filter "*.pdf"), copy matching files to a staging location, and sometimes capture clipboard data in a loop. Detections monitor recursive CLI searches targeting sensitive document types, or automated staging drops of these files in temp folders.
* Log Source Requirements: Endpoint logs capturing process creation events and file creation events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs recursive command-line directory searches targeting document files, and Event ID 11 (File Event) logs bulk file creation/drops in temp staging folders.
* NIDS (Suricata + Zeek): NO. Offline, local host actions.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
