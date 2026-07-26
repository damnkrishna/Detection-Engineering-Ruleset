### Technique Breakdown: T1129

* What it is: Shared Modules. Adversaries execute malicious payloads by loading them as shared modules (DLLs) into the memory space of trusted processes. This is frequently accomplished via DLL Search Order Hijacking, DLL Side-Loading, or AppInit DLLs. By forcing a signed, legitimate process (like `explorer.exe` or `svchost.exe`) to load a malicious module, the adversary executes code while hiding under the process identity of a trusted Windows system program.
* Log Source Requirements: Endpoint logs capturing module/image loads with digital signature verification (specifically Sysmon Event ID 7 - Image Loaded).
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 7 (Image Loaded) captures DLL loading events, reporting the path of the loading process, the path of the loaded DLL (`ImageLoaded`), and signature metadata.
* NIDS (Suricata + Zeek): NO. Shared module execution is local to the operating system's kernel and memory manager. It produces no network traffic.
* Log Sources Covered:
  - Sysmon Event ID 7 (image_load)
  - Sysmon Event ID 4104 (ps_script)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
