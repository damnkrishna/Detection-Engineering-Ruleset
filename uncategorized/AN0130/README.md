### Technique Breakdown: T1114.001

* What it is: Local Email Collection. Adversaries access locally stored email data files to harvest communications, credentials, or sensitive business information. On Windows, Microsoft Outlook stores email locally in Personal Storage Table files (.pst) and Offline Storage Table files (.ost) within the user's profile directory (%USERPROFILE%\Documents\Outlook Files\ or %LOCALAPPDATA%\Microsoft\Outlook\). Adversaries use shell commands, PowerShell, or custom tools to locate and copy these large data files.
* Log Source Requirements: Endpoint logs capturing file creation events and process creation events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 11 (File Event) captures file creation events for .pst/.ost files being copied or opened by non-Outlook processes. Sysmon Event ID 1 (Process Creation) logs command-line searches or file copy commands referencing Outlook files.
* NIDS (Suricata + Zeek): NO. Staging/access of email archives is host-local.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
