### Technique Breakdown

* What it is: System Script Proxy Execution. Adversaries may use trusted scripts signed by Microsoft (e.g., pubprn.vbs, manage-bde.wsf) to proxy execution of malicious code, bypassing application control policies that trust Microsoft-signed scripts.
* Log Source Requirements: Sysmon Process Creation (Event ID 1) / Windows Event ID 4688.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Command lines for script proxy execution are captured.
  - NIDS (Suricata + Zeek): NO. Host-local execution.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
