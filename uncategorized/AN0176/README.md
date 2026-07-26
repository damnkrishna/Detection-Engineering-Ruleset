### Technique Breakdown: T1574.009

* What it is: Hijack Execution Flow: Path Interception by Unquoted Path. Adversaries exploit unquoted service binary paths containing spaces to escalate privileges or establish persistence. When Windows starts a service whose binary path contains spaces and is not enclosed in double quotes (e.g., `C:\Program Files\Custom App\service.exe`), it interprets the spaces as delimiters and attempts to execute files in sequence: first `C:\Program.exe`, then `C:\Program Files\Custom.exe`, and finally `C:\Program Files\Custom App\service.exe`. If an attacker writes a malicious payload to `C:\Program.exe`, it will execute with the service's high privileges (often SYSTEM).
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters (specifically targeting service configuration tools creating new services).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs the execution of `sc.exe` or PowerShell command-lines creating or editing service definitions.
* NIDS (Suricata + Zeek): NO. Creating or editing services is a local operating system administrative task. It generates no network logs.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Windows System Log Event ID 7045 (system)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
