### Technique Breakdown

* What it is: Browser Session Hijacking. Adversaries hijack browser sessions to steal authentication cookies, session tokens, or credentials, allowing them to impersonate victims and access protected internal or cloud applications (such as intranets, email, or databases). On Windows systems, adversaries with administrative privileges or using specialized tools (like Mimikatz, SharpChromium, or browser-cookie stealers) inject malicious threads or access handles of active browser processes (like `chrome.exe`, `msedge.exe`, `firefox.exe`) to read session data directly from memory or database files.
* Log Source Requirements: Sysmon Process Access logs (Event ID 10) or CreateRemoteThread logs (Event ID 8) monitoring access to browser processes from scripting hosts or administrative tools.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 10 captures handles opened to browser processes with write/inject permissions. Event ID 8 captures remote thread injections into browser memory space.
    * NIDS (Suricata + Zeek): NO. Process handle access and thread injection are local operating system activities.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
