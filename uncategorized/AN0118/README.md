### Technique Breakdown: T1218.012

* What it is: Verclsid. Adversaries abuse `verclsid.exe`, a signed Windows binary (part of the Windows Shell), to execute arbitrary COM objects by supplying a CLSID argument. Since `verclsid.exe` is a trusted, Microsoft-signed binary, security products often allow it to instantiate COM objects. Attackers register a malicious COM object (or point to a remote SCT/HTA scriptlet via an existing CLSID) and invoke it through `verclsid.exe /S /C {CLSID}`. If the CLSID resolves to remote content, `verclsid.exe` makes outbound network connections, loading and executing the remote scriptlet.
* Log Source Requirements: Sysmon process creation logs (Event ID 1), Sysmon network connection logs (Event ID 3), and Sysmon registry modification logs (Event ID 12/13) capturing custom CLSID creation.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures `verclsid.exe` process creation with CLSID arguments. Event ID 3 captures outbound network connections initiated by `verclsid.exe`. Event ID 12/13 detects custom CLSIDs written to user classes.
    * NIDS (Suricata + Zeek): PARTIAL. Outbound network traffic from verclsid.exe can be captured, but local host context is needed for correlation.
* Log Sources Covered:
    - Sysmon Event ID 1 (process_creation)
    - Sysmon Event ID 3 (network_connection)
    - Sysmon Event ID 12/13 (registry_set)
* Log Sources Missing / Unused:
    - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
