### Technique Breakdown

* What it is: Modify Authentication Process: Reversible Encryption. Adversaries enable the "Store password using reversible encryption" setting (e.g. `UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED` in `userAccountControl`) for user accounts in Active Directory. This allows passwords to be stored as weakly encrypted ciphertexts, which can easily be decrypted to recover the user's plaintext password.
* Log Source Requirements: Windows Security Event logs (Event ID 4738 - User Account Changed, or Event ID 5136 - Directory Service Object Modified).
* Coverage Check:
  - HIDS (Sysmon + Windows Defender): NO. These are Active Directory changes audited via Windows Security Event Logs.
  - NIDS (Suricata + Zeek): NO. Encrypted AD LDAP or RPC traffic.
* Log Sources Covered:
  - Windows Security Event ID 4738 (service: security)
  - Windows Security Event ID 5136 (service: security)
* Log Sources Missing / Unused:
  - None.

### Blind Spots & Tuning

- Authorized IT administration activities.
- Tune with allowlists for known trusted execution paths.
