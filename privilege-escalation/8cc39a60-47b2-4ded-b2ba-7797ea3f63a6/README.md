### Technique Breakdown

* What it is: Abuse Elevation Control Mechanism. User Account Control (UAC) is a key Windows security feature that limits application privileges to standard user levels until an administrator authorizes an elevation. Adversaries bypass UAC by hijacking auto-elevated system binaries or hijacking COM objects and Registry paths to execute command payloads at High Integrity without triggering consent dialogs.
* Log Source Requirements: Endpoint logs capturing process creation events and registry modification events.
* Coverage Check:
  - HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures parent process paths, target process paths, and command-line arguments. Sysmon Event ID 13 captures direct registry writes targeting bypass keys.
  - NIDS (Suricata + Zeek): NO. Elevation of privileges is entirely a local operating system event.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 13 (registry_set)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
