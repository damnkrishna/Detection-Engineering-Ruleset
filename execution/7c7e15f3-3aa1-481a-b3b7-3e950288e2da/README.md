### Technique Breakdown

* What it is: Hijack Execution Flow: Executable Installer File Permissions Weakness. Adversaries exploit weak directory permissions in software installation paths (such as subfolders in `%TEMP%` or custom application directories created by installers) to overwrite or replace legitimate binaries with their own malicious payloads. When the installer runs again under an elevated context (e.g., local admin or SYSTEM), it executes the replaced binary, resulting in privilege escalation.
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters (specifically targeting elevated process execution originating from temporary or user-writable directories).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs process executions, including the full resolved path of the executable (`Image`) and the token elevation level (`IntegrityLevel`).
* NIDS (Suricata + Zeek): NO. Exploiting local installer directory permission weaknesses is an endpoint-internal privilege escalation method. It generates no network logs.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
