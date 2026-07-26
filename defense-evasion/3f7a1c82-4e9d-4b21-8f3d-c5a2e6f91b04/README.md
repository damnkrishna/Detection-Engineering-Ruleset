### Technique Breakdown

* What it is: BITS Jobs. Adversaries may abuse Windows Background Intelligent Transfer Service (BITS) to download, upload, or execute files while bypassing common defenses — BITS traffic blends with normal Windows Update traffic.
* Log Source Requirements: Sysmon Process Creation (Event ID 1) / Windows Event ID 4688.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. bitsadmin.exe and PowerShell BITS cmdlets produce command-line artifacts.
  - NIDS (Suricata + Zeek): PARTIAL. Outbound HTTP/S BITS traffic can be seen but is indistinguishable from Windows Update without context.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - Windows Event ID 59/60/61 (BITS transfer operational logs) could add coverage but are rarely forwarded.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
