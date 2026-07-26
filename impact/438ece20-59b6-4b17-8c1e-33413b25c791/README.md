### Technique Breakdown

* What it is: Network Denial of Service. Adversaries execute scripts or customized network stress engines on compromised endpoints to perform network flooding (e.g. UDP, TCP SYN, Slowloris HTTP floods) against external or internal target systems.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Flood utility executions and specific script command-line arguments are captured.
  - NIDS (Suricata + Zeek): YES. Flooding packets are highly visible at the network boundary.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
