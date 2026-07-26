### Technique Breakdown: T1546.011

* What it is: Event Triggered Execution: Application Shimming. The Microsoft Application Compatibility Infrastructure (shims) provides compatibility fixes for legacy programs. Adversaries exploit shims by creating custom shim databases (.sdb files) and installing them using the built-in command-line tool sdbinst.exe. Once registered, the compatibility database can be triggered when a specific application executes, allowing the attacker to inject malicious DLLs, bypass User Account Control (UAC), or hook APIs under a privileged execution context.
* Log Source Requirements: Endpoint logs capturing process creation events and file creation events.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs the execution of sdbinst.exe. Sysmon Event ID 11 (File Create) captures the creation of .sdb files under the AppPatch directory.
  - NIDS (Suricata + Zeek): NO. Application shimming is a local OS mechanism.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
