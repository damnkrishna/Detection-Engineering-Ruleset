### Technique Breakdown: T1546.001

* What it is: Event Triggered Execution: Change Default File Association. When a user double-clicks or opens a file, the Windows operating system executes the default application associated with that file extension (e.g., Notepad for .txt files). Adversaries modify these default associations (stored under HKLM\SOFTWARE\Classes or HKCU\Software\Classes) using utilities like assoc.exe or ftype.exe. This causes a malicious binary to run whenever a specific, commonly-opened file type is loaded.
* Log Source Requirements: Endpoint logs capturing process creation events and registry modifications.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs process execution of assoc.exe/ftype.exe and registry commands. Sysmon Event ID 13 captures direct registry writes.
  - NIDS (Suricata + Zeek): NO. Local configuration change.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
