### Technique Breakdown

* What it is: Archive Collected Data. Adversaries compress or encrypt collected data before exfiltration to minimize network bandwidth usage, speed up transfer times, and hide the contents of the files being stolen. They utilize standard administrative or packaging utilities (like `makecab.exe`, `7z.exe`, `rar.exe`, `tar.exe`) or built-in PowerShell commands. Host-based detection looks for command-line arguments specifying creation switches (e.g. `a`, `-cf`, `-p` for password protection) or using staging output directories.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) or Windows Security Event ID 4688 capturing command-line parameters of archiving utilities.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs process details, capturing command-line switches denoting archive creation and encryption (like adding passwords).
    * NIDS (Suricata + Zeek): NO. Local file archiving is a host-only filesystem operation.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
