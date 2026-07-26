### Technique Breakdown

* What it is: Forced Authentication. Adversaries may gather credential material by invoking or forcing a user's system to authenticate to a server they control, capturing NTLMv2 challenge/response hashes via SMB relay or Responder-style tools.
* Log Source Requirements: Sysmon Process Creation (Event ID 1) / Windows Security Event ID 4648.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. UNC path usage and .scf/.lnk file creation produce artifacts.
  - NIDS (Suricata + Zeek): YES. Outbound SMB to unexpected external IPs is detectable.
* Log Sources Covered:
  - Sysmon Event ID 11 (FileCreate) and Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - Network NTLM challenge/response capture requires NIDS rules outside Sigma scope.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
