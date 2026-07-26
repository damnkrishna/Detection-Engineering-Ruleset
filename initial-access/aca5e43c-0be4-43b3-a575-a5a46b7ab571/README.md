### Technique Breakdown

* What it is: Trusted Relationship. Adversaries exploit existing trust connections between target networks and external entities (such as IT managed service providers (MSPs), supply-chain partners, or vendor remote support services). Once they compromise the partner's network, they use legitimate remote access pathways (e.g., VPNs, remote desktop connections, or dedicated service accounts) to access the target environment, which makes distinguishing malicious activity from normal administration very difficult.
* Log Source Requirements: Windows Security Event Log Event ID 4624 (Logon) capturing Logon Types, user domains, and source IP addresses.
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Windows Security Event ID 4624 logs network logons (Logon Type 3) or RDP logons (Logon Type 10), and tracks the workstation name and IP. Wazuh aggregates these and alerts on anomalous combinations.
  * NIDS (Suricata + Zeek): YES. Network logs track connection activity from known third-party networks, but auditing the credentials used requires endpoint authentication logs.
* Log Sources Covered:
  - Windows Security Event ID 4624 (authentication)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Trusted relationship abuse can be detected using remote authentication logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
