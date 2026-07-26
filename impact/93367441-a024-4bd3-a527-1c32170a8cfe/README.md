### Technique Breakdown

* What it is: Data Encrypted for Impact. Adversaries encrypt data on target systems to disrupt system availability and demand ransom. To perform this, they use native tools or custom malware to traverse the filesystem, modify extensions, write ransom notes, and disable recovery paths.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688, and Sysmon File Creation events (Event ID 11).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 11 logs file creation details. Sysmon Event ID 1 logs execution parameters.
  - NIDS (Suricata + Zeek): NO. Host-local filesystem modifications.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
