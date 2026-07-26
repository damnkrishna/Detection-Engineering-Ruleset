### Technique Breakdown

* What it is: Financial Theft. Adversaries target retail endpoints, Point of Sale (POS) terminals, or billing servers to tamper with database transaction tables, modify accounting settings, or scrape credit card data from RAM, resulting in financial loss.
* Log Source Requirements: Sysmon Process Creation events (Event ID 1) / Security Event ID 4688, and Sysmon File Creation/Modification events (Event ID 11).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): YES. Scraping tools and database file writes are tracked.
  - NIDS (Suricata + Zeek): NO. Host-local application manipulation.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
