### Technique Breakdown

* What it is: Replication Through Removable Media. Adversaries copy malicious files (such as executables, shortcuts, or scripting payloads) to removable storage devices (like USB flash drives) to compromise other systems, especially air-gapped hosts. The detection monitors execution of scripts, interpreters, or binary utilities directly from removable media paths (e.g. drive paths mapped to typical removable letters like `D:\`, `E:\`, `F:\`, `G:\` etc., instead of the system partition `C:\`).
* Log Source Requirements: Sysmon process creation logs (Event ID 1) and PowerShell script block logs (Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures execution paths on non-system drives. Sysmon Event ID 4104 (Script Block) is effective at catching module loads or scripts referencing drive letters directly.
  * NIDS (Suricata + Zeek): NO. Network sensors have no visibility into local file system execution paths on physical host systems.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Replication through removable media execution can be detected using process creation and PowerShell script block logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
