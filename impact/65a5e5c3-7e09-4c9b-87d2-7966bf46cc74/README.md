### Technique Breakdown

* What it is: Endpoint Denial of Service: Application or System Exploitation. Adversaries exploit application or OS-level vulnerabilities (e.g. CVE-based exploits) to crash or restart system services, causing immediate service denial. This is frequently used to disable local security agents or disrupt server application availability (like Exchange or SQL databases).
* Log Source Requirements: Windows System Event Log (Event ID 7031 / 7034 / 7036 for SCM) and Sysmon Process Creation events (Event ID 1).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. SCM crash details and exploit process chains are captured.
  - NIDS (Suricata + Zeek): YES. If the exploit occurs over the network, network IDS can flag exploit packet patterns.
* Log Sources Covered:
  - Windows System Log Event ID 7031 (service_terminated_recovery)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
