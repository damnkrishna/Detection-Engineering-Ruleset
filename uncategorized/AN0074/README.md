### Technique Breakdown: T1547.012

* What it is: Boot or Logon Autostart Execution: Print Processors. The Windows print spooler service (spoolsv.exe) loads printer drivers and print processors during system startup or printer service initialization. Print processors are DLLs responsible for converting print job data into printer-ready formats. Adversaries can achieve privilege escalation and persistence by installing a malicious DLL as a custom print processor. They register it under the registry path HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\<CustomProcessor>\.
* Log Source Requirements: Endpoint logs capturing process creation events and registry modification events.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs CLI command lines modifying spooler registry paths. Sysmon Event ID 13 captures direct registry writes under Print Processor keys.
  - NIDS (Suricata + Zeek): NO. Host-level printer subsystem activity.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
