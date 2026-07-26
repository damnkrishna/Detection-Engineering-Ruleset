### Technique Breakdown: T1137.006

* What it is: Add-ins. Adversaries abuse Microsoft Office add-in mechanisms to achieve persistent code execution that triggers each time an Office application is launched. Add-in formats include Word WLL files (.wll), Excel XLL files (.xll), VBA add-ins (.xlam, .dotm), and COM-based add-ins registered in the Windows Registry. Adversaries drop a malicious add-in DLL or document into trusted add-in directories (e.g., %APPDATA%\Microsoft\Word\Startup\, %APPDATA%\Microsoft\Excel\XLSTART\) or add registry keys pointing to their payload.
* Log Source Requirements: Endpoint registry modification monitoring logs and file event logs capturing Office startup directory writes.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 12/13 monitors registry modifications, and Event ID 11 captures file creation events.
  - NIDS (Suricata + Zeek): NO. Host-level operations.
* Log Sources Covered:
  - Sysmon Event ID 13 (registry_set)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
