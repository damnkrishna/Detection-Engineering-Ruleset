### Technique Breakdown

* What it is: Data Manipulation: Transmitted Data Manipulation. Adversaries alter data in transit, such as web traffic, API payloads, or network packets. This is typically achieved by running network redirection software, configuring man-in-the-middle tools, or modifying system routing parameters (like the hosts file) to hijack lookup destinations.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1), Sysmon File Creation/Modification events (Event ID 11), and Sysmon Registry Set events (Event ID 13).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Process arguments, hosts file writing, and registry routing are fully monitored.
  - NIDS (Suricata + Zeek): YES. Network protocol changes can sometimes be seen, but host logs provide deterministic process attribution.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
