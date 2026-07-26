### Technique Breakdown: T1070.009

* What it is: Clear Persistence. Adversaries remove artifacts they previously planted for persistence — such as scheduled tasks, registry run keys, services, or startup folder binaries — to cover their tracks and hinder forensic investigation after completing their objectives. On Windows, removal commands include `sc.exe delete <service>`, `schtasks.exe /delete /tn <task>`, `reg.exe delete <key>`, or PowerShell equivalents (`Remove-Item`, `Unregister-ScheduledTask`). The detection pattern focuses on deletion of known persistence mechanisms rather than creation.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688), Sysmon registry deletion logs (Event ID 12/13), and Windows Security Event ID 4699 (scheduled task deleted).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures `sc.exe delete`, `schtasks.exe /delete`, and `reg.exe delete` commands. Event ID 12/13 captures registry value/key deletions. Windows Security Event ID 4699 logs scheduled task deletion events.
    * NIDS (Suricata + Zeek): NO. Persistence artifact removal is a host-local operation.
* Log Sources Covered:
    - Sysmon Event ID 1 (process_creation)
    - Sysmon Event ID 12/13 (registry_set)
    - Windows Security Event ID 4699 (service: security)
* Log Sources Missing / Unused:
    - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
