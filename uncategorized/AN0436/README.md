### Technique Breakdown: T1567.004

* What it is: Exfiltration Over Web Service: Exfiltration to Cloud Storage. Adversaries exfiltrate stolen data by posting it directly to public cloud storage or webhook receivers. They configure local scripts (e.g., PowerShell or curl) to execute HTTP POST requests containing file payloads targeting webhook URLs or cloud APIs. Because webhook platforms are legitimate and use standard port 443 HTTPS connections, they successfully bypass network boundary controls.
* Log Source Requirements: Endpoint logs capturing network connection events and process creation events.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 3 (Network Connection) logs outbound connections containing destination hostnames initiated by execution shells, and Event ID 1 (Process Creation) logs commands executing POST/PUT requests to webhook domains.
* NIDS (Suricata + Zeek): YES. TLS handshake metadata and SNI hostnames reveal webhook service connections.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
