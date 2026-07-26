### Technique Breakdown: T1546.008

* What it is: Event Triggered Execution: Accessibility Features. Windows accessibility tools (e.g., Sticky Keys sethc.exe, Utility Manager utilman.exe, On-Screen Keyboard osk.exe, Magnifier magnify.exe) can be launched using key combinations before a user logs in. Adversaries exploit this behavior by replacing these binary files with a command prompt (cmd.exe) or modifying the Image File Execution Options (IFEO) registry keys to assign a "Debugger" string pointing to a shell.
* Log Source Requirements: Endpoint logs capturing process creation events and registry modifications.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures accessibility binaries spawning command interpreters. Sysmon Event ID 13 (Registry Value Set) tracks direct registry overrides.
  - NIDS (Suricata + Zeek): NO. Host-local logon screen interactions.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
