### Technique Breakdown

* What it is: Audio Capture. Adversaries capture audio from the host microphone using local APIs or recording tools. They use this capability for room monitoring or industrial espionage. On Windows endpoints, audio recording requires interacting with the Windows Multimedia API or DirectSound, which involves loading libraries like `winmm.dll` or `dsound.dll`. Identifying unsigned or anomalous processes loading these DLLs is a primary host-based detection approach.
* Log Source Requirements: Sysmon Library Load logs (Event ID 7) or process creation logs (Event ID 1).
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 7 logs when applications load `winmm.dll` or `dsound.dll`. Wazuh correlates these to trigger alerts.
    * NIDS (Suricata + Zeek): NO. Network sensors monitor IP streams and cannot track physical audio card capture states.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
