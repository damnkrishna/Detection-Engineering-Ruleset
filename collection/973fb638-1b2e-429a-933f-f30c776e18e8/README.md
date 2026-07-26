### Technique Breakdown
* What it is: Adversary-in-the-Middle: ARP Cache Poisoning. Adversaries send malicious ARP packets onto a local network to associate their MAC address with the IP address of another host (typically the default gateway). This redirects network traffic destined for that host through the attacker's system.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Captures command-line arguments of tools modifying routing tables or sending raw packets.
  - NIDS (Suricata + Zeek): YES. Specialized NIDS rules can flag duplicate IP-to-MAC assignments or high-rate gratuitous ARP traffic.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
