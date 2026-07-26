# User Logon Initialization Script Registry Modification (AN2112)

## Metadata
- **Rule ID**: f1a2b3c4-e5f6-7a8b-9c0d-1e2f3a4b5c90
- **Technique**: T1037

## Details
Detects modifications to Windows registry keys that configure user logon or initialization scripts (such as UserInitMprLoopbackScript or Userinit parameters), which can be abused by adversaries to achieve persistent execution during user logon.
