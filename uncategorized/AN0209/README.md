### Technique Breakdown: T1059.005

* What it is: Visual Basic. Adversaries abuse the Windows Script Host (WSH) engine (via interpreters like `wscript.exe` and `cscript.exe`) to execute malicious Visual Basic scripts (`.vbs`, `.vbe`, or `.vba`). This is a common execution method used in phishing attacks, where a malicious macro in an Office document (Word, Excel) spawns a VBScript file, or a user runs a downloaded `.vbs` script disguised as a document.
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters (specifically targeting built-in script hosts spawned by Office applications or running from temporary directories).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs the execution of `wscript.exe` or `cscript.exe` and records command-line flags showing the executed script paths. It also logs parent-child process relationships (e.g., Office applications spawning script hosts).
* NIDS (Suricata + Zeek): NO. VBScript execution is a local endpoint activity. Network security tools cannot inspect host-internal script execution (though they might alert on the initial download of the `.vbs` file or outbound C2 traffic).
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
