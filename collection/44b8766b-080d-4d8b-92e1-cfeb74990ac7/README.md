### Technique Breakdown
* What it is: Adversary-in-the-Middle. Adversaries position themselves between two or more networked devices to capture, modify, or inject traffic. This is typically used to harvest credentials or session tokens passing over the network.
* Log Source Requirements: Sysmon Process Creation logs (Event ID 1).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Process creation command lines capture the invocation of scripting interpreters with proxy listener flags.
  - NIDS (Suricata + Zeek): YES. Can detect network-level AiTM redirects via unexpected gateway changes.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
