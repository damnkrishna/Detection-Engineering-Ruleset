### Technique Breakdown

* What it is: Wi-Fi Networks. Adversaries leverage rogue Wi-Fi access points (like Evil Twins) or connect corporate laptops to unauthorized, unencrypted public wireless networks to intercept traffic, perform man-in-the-middle (MitM) attacks, or bypass corporate egress filters. Detection involves monitoring processes executing wireless profile queries (e.g. netsh wlan show profiles).
* Log Source Requirements: Sysmon process creation logs (Event ID 1) and PowerShell script block logs (Event ID 4104).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures network configuration queries (like netsh.exe wlan). Sysmon Event ID 4104 (Script Block) captures wireless profile queries executed via PowerShell commands.
  * Windows Security/Defender Logs: NO. These logs do not natively record Wi-Fi client association details unless specific verbose tracing is enabled in custom channels.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Querying of wireless network profiles can be detected using process creation and PowerShell script block logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
