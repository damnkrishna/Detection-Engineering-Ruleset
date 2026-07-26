### Technique Breakdown

* What it is: Encrypted Channel: Symmetric Cryptography. Adversaries encrypt their Command and Control (C2) traffic using symmetric encryption algorithms (e.g., AES or RC4) to evade signature-based network inspection. Malware binaries running on Windows often call built-in cryptographic libraries (CNG/CryptoAPI) by loading DLLs such as bcryptprimitives.dll, bcrypt.dll, or cryptsp.dll. When non-cryptographic system binaries (like calc.exe or notepad.exe) load these DLLs and subsequently open network sockets, it indicates process injection and custom C2 encryption.
* Log Source Requirements: Endpoint image load logs (Sysmon Event ID 7 / Windows Security Event ID 5056) and Network Connection logs (Sysmon Event ID 3).
* Coverage Check:
    * HIDS (Sysmon + Windows Defender): YES. Sysmon Event ID 7 captures DLL loading events. Event ID 3 logs outbound network connections.
    * Windows Security Logs: PARTIAL. Security logs Event ID 5056 captures image loads if configured.
* Log Sources Covered:
    - Sysmon Event ID 7 (image_load)
    - Sysmon Event ID 3 (network_connection)
* Log Sources Missing / Unused:
    - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
