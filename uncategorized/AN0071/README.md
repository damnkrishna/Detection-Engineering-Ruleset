### Technique Breakdown: T1218.015

* What it is: Electron Applications. Adversaries abuse trusted Electron-based desktop applications (such as Microsoft Teams, Slack, VS Code, Discord, or Chrome) as proxy execution vehicles for malicious payloads. Because these apps are signed by trusted vendors and widely installed, security tools often allow them. Attackers exploit Electron's Node.js runtime via command-line flags like `--gpu-launcher`, `--renderer-startup-dialog`, or `--inspect` to spawn arbitrary child processes or achieve code execution within the app's sandbox. Alternatively, modifying `.asar` archive files (the bundled app resource format) allows persistent injection into the Electron app itself.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) capturing Electron app parent processes spawning unusual children, image load events (Event ID 7) for node.dll/electron.dll loads, and file write events (Event ID 11) for .asar modifications.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 captures the Electron parent process with command-line flags, and child processes spawned. Event ID 7 captures DLLs loaded, and Event ID 11 logs file writes.
    * NIDS (Suricata + Zeek): NO. Electron app abuse is host-local. The proxy execution produces no network anomalies at first.
* Log Sources Covered:
    - Sysmon Event ID 1 (process_creation)
    - Sysmon Event ID 7 (image_load)
    - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
    - None.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
