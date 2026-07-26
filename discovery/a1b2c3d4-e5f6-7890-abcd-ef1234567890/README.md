### Technique Breakdown

* What it is: Network Share Discovery. Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather or as a precursor to Lateral Movement.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688.
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Process command lines are captured.
  - NIDS (Suricata + Zeek): YES. SMB traffic enumeration is detectable on the wire.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
