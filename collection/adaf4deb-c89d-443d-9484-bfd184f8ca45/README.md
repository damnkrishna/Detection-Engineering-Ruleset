### Technique Breakdown

* What it is: Local Data Collection. Adversaries search local system directories (such as user desktops, document directories, or mail caches) to collect sensitive files prior to exfiltration. They run command loops (like `dir /s` or `Get-ChildItem` in PowerShell) targeting specific file extensions (such as `.docx`, `.pdf`, `.xlsx`, `.pst`, `.db`) and write these matching paths to a staging file or staging directory.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) capturing command-line parameters, combined with PowerShell Script Block logs (Event ID 4104).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures the search loops containing wildcards (e.g., `*.docx`). Wazuh aggregates these and alerts.
    * NIDS (Suricata + Zeek): NO. Network sensors have no visibility into local file search commands or local drive audits.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
