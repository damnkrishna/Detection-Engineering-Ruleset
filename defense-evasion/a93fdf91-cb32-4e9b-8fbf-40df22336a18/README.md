### Technique Breakdown

* What it is: Hidden Files and Directories. Adversaries set the hidden attribute on files or directories to conceal their malicious artifacts from casual inspection by users or administrators. On Windows, this is done using `attrib.exe +H` (to set the hidden attribute) or `attrib.exe +H +S` (to set both hidden and system attributes, making files invisible in default Explorer views). Alternatively, adversaries create files in Alternate Data Streams (ADS) using the `filename:streamname` notation, hiding payloads inside what appears to be a legitimate file.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) for `attrib.exe` and PowerShell invocations, and Sysmon file event logs (Event ID 11) for ADS file creation.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures `attrib.exe +H` commands with file targets. Sysmon Event ID 11 logs file creation events, and the `TargetFilename` field includes the ADS stream notation (`:streamname`) which can be used to detect ADS writes.
    * NIDS (Suricata + Zeek): NO. Setting file attributes or writing ADS streams are host-local filesystem operations.
* Log Sources Covered:
    - Sysmon Event ID 1 (process_creation)
    - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
    - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
