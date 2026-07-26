# Social Engineering Script-Based Credential Dialog Prompt (AN2128)

## Metadata
- **Rule ID**: f1a2b3c4-e5f6-7a8b-9c0d-1e2f3a4b5c89
- **Technique**: T1684

## Details
Detects process command line arguments indicating the spawning of credential dialog boxes or login forms (such as PowerShell Get-Credential or MSHTA HTML forms) used in post-exploitation to trick users into typing administrative passwords.
