### Technique Breakdown: T1496.002

* What it is: Resource Hijacking: Joint Bandwidth Hijacking. Adversaries hijack a compromised system's network bandwidth to run proxy services (known as proxyjacking, e.g., Honeygain, EarnApp, PacketStream) or execute botnet-driven scanning tasks. This allows the attacker to monetize the victim's internet connection or route malicious traffic through their IP space, resulting in severe performance degradation and reputation blacklisting. Detections monitor the execution of known bandwidth-sharing or high-volume scanning binaries and their associated network activity.
* Log Source Requirements: Endpoint logs capturing process creation (Sysmon Event ID 1 / Windows Security Event ID 4688) and network connection logs (Sysmon Event ID 3).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 logs the execution of proxyjacking client files. Sysmon Event ID 3 captures outbound socket connections to bandwidth-sharing coordinator nodes.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Proxyjacking and bandwidth hijacking activity can be detected using process creation and network connection logs.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
