### Technique Breakdown

* What it is: Resource Hijacking. Adversaries leverage compromised endpoint resources for unauthorized utility, typically for cryptomining (e.g. Monero mining). They deploy binaries or scripts that run persistently in the background, consuming CPU, GPU, and network resources.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) and Sysmon Network Connection events (Event ID 3).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Miner binaries and command lines are detected via process creation. Outbound pool network traffic is detected via network connections.
  - NIDS (Suricata + Zeek): YES. Stratum protocol signatures on outbound ports can be flagged by network IDS.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
