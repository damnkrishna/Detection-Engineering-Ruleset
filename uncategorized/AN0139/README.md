### Technique Breakdown: T1564.012

* What it is: File/Path Exclusions. Adversaries exploit the fact that security tools (antivirus engines, EDR agents) maintain exclusion lists — directories, file paths, or extensions that are excluded from scanning or monitoring. By placing malicious files in excluded paths (e.g., `C:\Windows\Temp`, Exchange server directories, or custom AV exclusion paths set by admins), adversaries ensure their payloads are not scanned or detected. They may also actively add new exclusions using `powershell.exe Add-MpPreference` or registry modifications to create blind spots for their malware.
* Log Source Requirements: Sysmon process creation logs (Event ID 1), Windows Security Event ID 4688 (process creation), and Sysmon registry modification logs (Event ID 13) capturing Defender exclusions.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures PowerShell `Add-MpPreference -ExclusionPath` commands. Event ID 13 captures direct exclusion writes in the registry.
    * NIDS (Suricata + Zeek): NO. Exclusion list manipulation is a host-local operation.
* Log Sources Covered:
    - Sysmon Event ID 1 (process_creation)
    - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
    - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
