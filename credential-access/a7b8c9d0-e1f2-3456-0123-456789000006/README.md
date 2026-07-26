### Technique Breakdown

* What it is: Network Sniffing. Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Process command lines for known packet capture utilities are captured.
  - NIDS (Suricata + Zeek): NO. NIDS itself is the target tool class; anomaly detection on the host is required.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
