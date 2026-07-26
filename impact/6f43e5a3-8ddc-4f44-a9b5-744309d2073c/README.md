### Technique Breakdown

* What it is: Network Denial of Service: Direct Network Flood. Adversaries generate a high volume of network traffic directly targeting a victim to saturate network interfaces, exhaust state tables, or crash endpoints. They achieve this using dedicated flooding tools (such as LOIC or HOIC) or custom scripts executing rapid connection loops.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688, and Sysmon Network Connection events (Event ID 3).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Flood binaries and process executions are tracked. Outbound connection rates are audited via Sysmon EID 3.
  - NIDS (Suricata + Zeek): YES. Network sensors are highly effective at detecting flood volumes at the network layer.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
