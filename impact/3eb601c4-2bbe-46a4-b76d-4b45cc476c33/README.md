### Technique Breakdown

* What it is: Endpoint Denial of Service. Adversaries target endpoints with resource exhaustion attacks or cause unexpected service terminations. The goal is to disable security controls, disrupt logging agents (like Sysmon, Wazuh, Defender), or crash business-critical server applications to prevent response or trigger outages.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Windows Security Event ID 4688, and Windows System Event Log (Event ID 7034).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Sysmon tracks stressing utilities; Windows System logs track service terminations.
  - NIDS (Suricata + Zeek): NO. Host-local resource and service states.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Windows System Log Event ID 7034 (service_terminated_unexpectedly)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
