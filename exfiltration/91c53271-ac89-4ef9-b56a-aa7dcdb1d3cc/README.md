### Technique Breakdown

* What it is: Exfiltration Over Physical Medium: Bluetooth-Based Data Exfiltration. Adversaries exfiltrate data from a compromised host to a nearby rogue device (such as a smartphone or laptop) over Bluetooth, bypassing corporate network egress monitoring. On Windows systems, this is typically facilitated using the native Bluetooth File Transfer wizard executable, `fsquirt.exe`, or by utilizing command-line tools that interact with Bluetooth APIs.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) auditing user execution of Bluetooth transfer wizards.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs process creations, including the path and name of `fsquirt.exe`. Wazuh tracks this event to alert on execution.
    * NIDS (Suricata + Zeek): NO. Network security appliances monitor IP network interfaces and cannot audit local Bluetooth radio frequencies.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
