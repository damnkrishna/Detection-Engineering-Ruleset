### Technique Breakdown

* What it is: Use Alternate Authentication Material: Pass the Ticket. Adversaries hijack Kerberos Ticket Granting Tickets (TGT) or Service Tickets (TGS) to authenticate to remote resources without knowing the user's password. They inject stolen tickets into their local LSASS session (e.g., using Rubeus or Mimikatz). Detection focuses on identifying Kerberos Ticket requests (Event ID 4768/4769) containing anomalous or weak encryption types (like RC4-HMAC, 0x17 / 23), or process creations referencing ticket injection command parameters.
* Log Source Requirements: Windows Security Event Log Event ID 4768 (TGT requested) and Event ID 4769 (Service Ticket requested), or Sysmon process creation logs (Event ID 1).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Windows Security log audits Kerberos service requests. Sysmon Event ID 1 logs ticket injection tool parameters (e.g., rubeus.exe ptt). Wazuh parses these logs to trigger alerts.
  * NIDS (Suricata + Zeek): YES. Network sensors monitor Kerberos ticket request traffic and flag anomalous encryption algorithms.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Windows Security Log Event ID 4768 (security)
  - Windows Security Log Event ID 4769 (security)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Pass the ticket activity can be detected using process creation and security authentication logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
