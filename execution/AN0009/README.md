### Technique Breakdown

* What it is: Hijack Execution Flow: Path Interception by PATH Environment Variable. Adversaries modify the Windows `PATH` environment variable to intercept execution flows. By appending a user-writable folder (like `%TEMP%` or a local program path) to the beginning of the `PATH` variable, the operating system will search that folder first when launching executables. If an administrator or service runs a system tool (like `taskkill` or `ping`) without specifying the full path, the OS will load and execute the attacker's malicious binary of the same name.
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters (specifically targeting tools that modify system environment variables).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs the execution of utilities like `setx.exe`, `reg.exe`, or PowerShell command-lines modifying environment configurations.
* NIDS (Suricata + Zeek): NO. Environment variable configuration is a local operating system task. It generates no network logs.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
