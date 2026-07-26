### Technique Breakdown

* What it is: Data Manipulation: Runtime Data Manipulation. Adversaries modify data in memory or during runtime execution to alter transaction values, bypass checks, or steal retail cards (e.g., POS RAM scraping). They achieve this by injecting threads or acquiring process handles with write access targeting active business/database processes.
* Log Source Requirements: Sysmon Process Access events (Event ID 10) and Sysmon CreateRemoteThread events (Event ID 8).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. API calls requesting write handles and remote threads are natively monitored.
  - NIDS (Suricata + Zeek): NO. Host-local memory space operations.
* Log Sources Covered:
  - Sysmon Event ID 10 (process_access)
  - Sysmon Event ID 8 (create_remote_thread)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
