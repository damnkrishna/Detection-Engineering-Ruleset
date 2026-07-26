### Technique Breakdown

* What it is: Safe Mode Boot. Adversaries force a system to boot into Windows Safe Mode to disable security features (like antivirus, EDRs, and network monitoring agents) that do not load in this minimal environment. Attackers achieve this by using the command-line utility `bcdedit.exe` to configure the system to boot into Safe Mode (`minimal` or `network`) on the next restart. Alternatively, they modify the registry keys under `SafeBoot` to allow their own malware or malicious drivers to execute even in Safe Mode.
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters (specifically targeting boot configuration and registry utilities).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs the execution of utilities like `bcdedit.exe` or `reg.exe` targeting boot configuration parameters.
* NIDS (Suricata + Zeek): NO. Configuring boot options is a local operating system administrative task. It generates no network telemetry.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
