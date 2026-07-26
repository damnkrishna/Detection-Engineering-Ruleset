### Technique Breakdown: T1053

* What it is: Scheduled Task/Job. Adversaries register scheduled tasks or jobs to execute malicious code automatically on a system. This technique is commonly used for persistence (running code across system reboots), execution (spawning payloads), or privilege escalation (configuring tasks to run under the high-privilege `SYSTEM` context). On Windows, tasks are typically created using the native `schtasks.exe` utility, the legacy `at.exe` utility, or PowerShell Task Scheduler cmdlets.
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters (specifically targeting command line schedulers or script block logs).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs the invocation of tools like `schtasks.exe` or `at.exe`, and records command-line flags.
* NIDS (Suricata + Zeek): NO. Creating scheduled tasks is a host-local configuration action. It produces no direct network traffic.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
