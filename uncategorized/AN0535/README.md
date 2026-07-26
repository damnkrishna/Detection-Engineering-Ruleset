### Technique Breakdown: T1685.001

* What it is: Disable or Modify Windows Event Log. Adversaries impair Windows event logging to hide their actions, prevent forensic analysis, and bypass security alerts. They do this by clearing log channels using native tools like `wevtutil.exe`, disabling specific event channels in the registry, modifying system audit policies via `auditpol.exe` to stop recording high-risk activities, or forcibly stopping/disabling the EventLog service.
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters (specifically target administrative tools used to stop services, adjust audit policies, or configure log channels).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs the execution of utilities like `wevtutil.exe`, `auditpol.exe`, `sc.exe`, or PowerShell commands targeting event services.
* NIDS (Suricata + Zeek): NO. Impairing local system logging is an endpoint-internal operation. It generates no network signatures.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
