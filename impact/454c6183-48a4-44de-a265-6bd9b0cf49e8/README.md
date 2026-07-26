### Technique Breakdown

* What it is: Network Denial of Service: Reflection Amplification. Adversaries abuse misconfigured internet services (like DNS, NTP, SNMP, Memcached) to reflect and amplify traffic toward a target. To execute this from a compromised host, the adversary sends rapid request packets spoofing the target's IP address, or uses scripts to trigger high-rate queries targeting known reflective nodes.
* Log Source Requirements: Sysmon Network Connection events (Event ID 3) and Sysmon Process Creation events (Event ID 1).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Outbound connection rates and interpreter processes are monitored.
  - NIDS (Suricata + Zeek): YES. Amplified outbound traffic on ports 53/123/161 can be seen at network egress checkpoints.
* Log Sources Covered:
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
