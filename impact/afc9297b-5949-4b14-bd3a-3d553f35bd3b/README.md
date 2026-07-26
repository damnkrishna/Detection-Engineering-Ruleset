### Technique Breakdown

* What it is: Endpoint DoS: Service Exhaustion Flood. Adversaries degrade the availability of critical host applications (like local web services, database services, or API endpoints) by flooding them with high-frequency network connection requests (such as TCP SYN floods, slow-connection attacks, or TLS renegotiations). Detections monitor for execution of load testing/flooding tools or command-line scripting interpreters executing connection loops targeting web services, and the resulting high-frequency outbound network connections.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) tracking execution, and network connection logs (Sysmon Event ID 3).
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 logs CLI command parameters for flooding/testing utilities. Sysmon Event ID 3 captures outbound socket connections.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Service exhaustion flood tool execution can be detected using process creation and network connection logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
