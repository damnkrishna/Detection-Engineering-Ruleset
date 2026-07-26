### Technique Breakdown: T1668

* What it is: Exclusive Control. Adversaries establish exclusive control over a compromised system by self-patching or disabling the vulnerability they used to gain initial access, preventing other threat actors from exploiting the same weakness and competing for control of the host. This post-exploitation behavior includes stopping or patching vulnerable services, modifying firewall rules to block the exploit path, or terminating other malicious processes on the host.
* Log Source Requirements: Endpoint logs capturing process creation events and system logs capturing service state changes.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures sc.exe, net.exe, and taskkill.exe executions. System Event ID 7036 logs service state transitions.
  - NIDS (Suricata + Zeek): NO. Service stopping and process termination are host-local operations.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - System Event ID 7036 (system)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
