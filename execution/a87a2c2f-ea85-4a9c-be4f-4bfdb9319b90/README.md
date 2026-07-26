### Technique Breakdown

* What it is: Lua. Adversaries abuse built-in or dropped Lua interpreters (`lua.exe`, `luac.exe`, `wlua.exe`) to execute Lua scripts (`.lua`). Lua is a lightweight scripting language often embedded in game clients, network software (like Nmap or Wireshark), or security tools. Attackers drop standalone Lua interpreters to execute malicious payload scripts, avoiding detection systems that only monitor PowerShell, VBScript, or command shells.
* Log Source Requirements: Endpoint logs capturing process creation and command line parameters (specifically targeting standalone Lua execution or interpreters spawned by suspicious parent processes).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs the execution of Lua interpreters, including their command-line arguments and parent process names.
* NIDS (Suricata + Zeek): NO. Lua script execution is local. Network logs cannot detect the execution itself (though they might alert on script downloads or C2 network traffic).
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
