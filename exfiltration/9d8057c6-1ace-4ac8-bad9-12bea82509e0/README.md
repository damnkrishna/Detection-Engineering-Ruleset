### Technique Breakdown

* What it is: Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol. Adversaries encrypt sensitive data using asymmetric cryptography (such as RSA or GPG) before transmitting it externally. By encrypting the data with a public key, the adversary ensures that intermediate network security controls (such as NIDS or DLP) cannot decrypt and inspect the payload, even if they decrypt the outer SSL/TLS tunnel. Host-based detection focuses on identifying processes executing command-line utilities (like `openssl.exe` or `gpg.exe`) or using scripting libraries to encrypt files.
* Log Source Requirements: Sysmon process creation logs (Event ID 1) capturing command line arguments.
* Coverage Check:
    * HIDS (Sysmon + Wazuh): YES. Sysmon Event ID 1 logs the full command-line arguments, letting defenders detect commands like `gpg --encrypt` or `openssl rsautl`. Wazuh parses these logs to alert.
    * NIDS (Suricata + Zeek): NO. Network sensors see only encrypted blobs and cannot detect the asymmetric encryption step on the host.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
