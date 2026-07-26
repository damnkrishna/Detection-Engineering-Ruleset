### Technique Breakdown

* What it is: Supply Chain Compromise: Compromise Hardware Supply Chain. Adversaries insert malicious physical modifications or subverted firmware (such as tampered UEFI/BIOS, customized network cards, or compromised baseboard management controllers) during manufacturing or distribution. Detecting this post-delivery requires monitoring host BIOS flashing utilities, TPM validation errors, or Secure Boot policy changes.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) and Sysmon driver load logs (Event ID 6).
* Coverage Check:
  * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 tracks BIOS flashing tool executions. Sysmon Event ID 6 tracks the kernel-mode drivers loaded by these flashing utilities.
  * Windows Security/Defender Logs: NO. These sources do not capture low-level firmware changes directly, though UEFI/Secure Boot logs can be queried via advanced firmware interfaces.
* Log Sources Covered:
  - Sysmon Event ID 1 (process_creation)
  - Sysmon Event ID 6 (driver_activity)
* Log Sources Missing / Unused:
  - None.
* Conclusion: Hardware supply chain firmware flashing and driver load can be detected using process creation and driver load logs.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
