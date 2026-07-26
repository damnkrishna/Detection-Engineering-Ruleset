### Technique Breakdown

* What it is: Use Alternate Authentication Material: Pass the Hash. Adversaries authenticate to remote systems using NTLM password hashes instead of cleartext passwords. By passing the hash directly to the local security provider (LSASS), they establish remote sessions without password knowledge. On Windows target systems, a successful Pass the Hash network logon is characterized by a Network Logon (Event ID 4624, Logon Type 3) using NTLM authentication where the Key Length is recorded as 0, because the normal NTLM challenge-response key derivation step is bypassed.
* Log Source Requirements: Windows Security Event Log Event ID 4624 (Logon) auditing NTLM parameters.
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Windows Security log captures Event ID 4624 details including Logon Type, Authentication Package, and Key Length. Wazuh parses and alerts on these fields.
  * NIDS (Suricata + Zeek): PARTIAL. Network sensors track NTLM sessions but cannot inspect the inner LSASS session parameters or key length structures.
* Log Sources Covered:
  - Windows Security Log Event ID 4624 (security)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Pass the hash activity can be detected using logon logs and process creation logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
