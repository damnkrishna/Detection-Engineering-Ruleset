### Technique Breakdown

* What it is: Defacement: External Defacement. Adversaries modify content or resources on external services (such as CDN endpoints, public DNS registries, or corporate landing pages hosted externally) to display messages, redirect traffic, or damage the organization's reputation.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688, and Sysmon File Creation/Modification events (Event ID 11).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Outbound deployment script arguments and local DNS server zone file writes are monitored.
  - NIDS (Suricata + Zeek): NO. Host-local deployment or zone modification execution.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
