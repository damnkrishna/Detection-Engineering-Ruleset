### Technique Breakdown

* What it is: Modify Authentication Process. Adversaries modify authentication mechanisms to bypass access controls or intercept credentials. Under this technique, adversaries register malicious DLLs as Password Filter DLLs or LSA packages (T1556.002). By modifying registry keys under the Local Security Authority (LSA), they configure LSA to load a malicious DLL. When users log in or modify their passwords, the malicious package intercepts credentials in cleartext.
* Log Source Requirements: Registry modification logs (Sysmon Event ID 13) tracking LSA packages keys and host process creation and command line logs (Sysmon Event ID 1 / Windows Security Event ID 4688) tracking reg.exe command execution.
* Coverage Check:
  * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 13 (Registry Set) is perfectly positioned to catch this modification. Sysmon Event ID 1 captures command-line registry tool usage.
  * Windows Security Logs: YES. Standard Security Logs capture registry write auditing if configured, and process execution command lines (Event ID 4688).
* Log Sources Covered:
  - Sysmon Event ID 13 (registry_set)
  - Sysmon Event ID 1 (process_creation)
* Log Sources Missing / Unused:
  - None.
* Conclusion: LSA registry package modifications can be detected using registry events and command line logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
