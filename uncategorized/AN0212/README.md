### Technique Breakdown: T1011

* What it is: Exfiltration Over Other Network Medium. Adversaries bypass corporate firewall and proxy monitors by exfiltrating data through non-primary network interfaces connected directly to the internet (such as local WiFi hotspots, mobile cellular adapters, or Bluetooth links). Detections focus on identifying command-line configurations of wireless adapters or registry modifications of Bluetooth drivers, indicating out-of-band network staging.
* Log Source Requirements: Endpoint logs capturing process creation and registry modifications.
* Coverage Check:
* HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 (Process Creation) logs commands querying/configuring wireless interfaces, and Event ID 13 (Registry Set) logs Bluetooth service configuration modifications.
* NIDS (Suricata + Zeek): NO. Traffic bypasses corporate security boundary proxies and gateways.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
