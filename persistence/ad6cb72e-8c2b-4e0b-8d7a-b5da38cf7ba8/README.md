### Technique Breakdown

* What it is: IIS Components. Adversaries install malicious Internet Information Services (IIS) components — including ISAPI filters, ISAPI extensions, or IIS native modules — to achieve persistent code execution on Windows web servers. These components are DLLs that the IIS worker process (w3wp.exe) loads automatically, intercepting or manipulating HTTP requests and responses. Adversaries use the IIS administration tool appcmd.exe to register the DLL, or directly modify IIS configuration files (applicationHost.config).
* Log Source Requirements: Endpoint logs capturing process creation events and file creation events in web server directories.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures appcmd.exe or PowerShell module registrations. Event ID 11 captures DLL file drops in system folders.
  - NIDS (Suricata + Zeek): NO. Host-local configuration changes.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
