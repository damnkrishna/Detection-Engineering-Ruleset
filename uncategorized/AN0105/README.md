### Technique Breakdown: T1555.003

* What it is: Credentials from Password Stores: Credentials from Web Browsers. Adversaries search for and extract the local files where web browsers (like Chrome, Edge, and Firefox) store saved usernames, passwords, and session cookies. These are typically SQLite databases (like Login Data or Cookies) or JSON files.
* Log Source Requirements: Host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) tracking execution, and file system logs (Sysmon Event ID 11) tracking file creation or access.
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 1 (Process Creation) is highly effective at catching Living off the Land (LotL) techniques where attackers use native commands (copy, xcopy, tar) to stage these database files for exfiltration. Sysmon Event ID 11 (File Event) tracks unauthorized files being accessed or copied by non-browser processes.
  * Windows Security Logs: YES. Standard Security Logs track process execution (Event ID 4688) containing the command line arguments.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 11 (file_event)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Browser credential store access attempts using command line utilities can be detected using process creation and command line logs. Access by unauthorized processes to credential store files can be detected using file event logs.


* Benign 3: Brave Browser Operation (Rule 2 Filter)
  * The Log: File Event with Image `brave.exe` reading the Brave `Login Data` file.
  * Expected Outcome: The `Image` explicitly matches the `filter_browsers` allowlist (`\brave.exe`). MUST NOT trigger an alert.

### Blind Spots & Tuning (The "Problems")

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
