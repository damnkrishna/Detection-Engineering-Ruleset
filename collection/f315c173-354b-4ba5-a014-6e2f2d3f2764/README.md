# Suspicious Module Load in Interactive User Processes (AN0282-B)

## Metadata
- **Rule ID**: f315c173-354b-4ba5-a014-6e2f2d3f2764
- **Technique**: T1056

## Details
Detects loading of DLLs from user-writable directories into interactive user shells and web browsers, excluding known signed updater and native-host binaries.
