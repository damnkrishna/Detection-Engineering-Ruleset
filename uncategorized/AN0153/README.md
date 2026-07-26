### Technique Breakdown: T1553.004

* What it is: Install Root Certificate. Adversaries install untrusted root certificates into the victim's Trusted Root Certification Authorities store to subvert trust controls. Once installed, the operating system and web browsers will trust any TLS/SSL certificate signed by the adversary's certificate authority (CA). This allows adversaries to perform middle-person (MitM) inspection of encrypted traffic, bypass code signing restrictions (allowing malware to run as "trusted" signed software), or establish persistence.
* Log Source Requirements: Endpoint logs capturing process execution and command line parameters (specifically administrative certificate utility tools like `certutil.exe`, `certmgr.exe`, or PowerShell command-lines).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs the execution of utilities like `certutil.exe`, `certmgr.exe`, or PowerShell cmdlets with parameters containing flags like `-addstore` or `/add` directed at the `root` store.
* NIDS (Suricata + Zeek): NO. Certificate store modification is a host-local configuration change. It does not produce a distinct network signature (though network tools may observe the resulting decrypt-and-inspect MitM activity later).
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
