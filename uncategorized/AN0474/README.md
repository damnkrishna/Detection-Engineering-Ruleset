### Technique Breakdown: T1495

* What it is: Firmware Corruption. Adversaries modify or corrupt system firmware (such as UEFI, BIOS, or hard drive controller firmware) to make the target system completely inoperable and brick the hardware. In Windows environments, firmware or boot sequence tampering is preceded by command-line execution of tools like bcdedit.exe to modify the Boot Configuration Data (BCD) store, disabling boot recovery menus (recoveryenabled No) or configuring the OS to ignore boot failures (bootstatuspolicy ignoreallfailures), preventing recovery.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) tracking execution, and PowerShell script block logs (Sysmon Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 captures bcdedit.exe executions with full command parameters. Sysmon Event ID 4104 (Script Block) captures scripts modifying boot loader properties.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Boot configuration tampering can be detected using process creation and PowerShell script block logs.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
