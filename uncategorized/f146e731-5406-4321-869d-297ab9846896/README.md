# Network Provider DLL Registry Modification and File Creation (AN1598-A/B)

## Metadata
- **Rule ID**: f146e731-5406-4321-869d-297ab9846896
- **Technique**: T1556.008

## Details
Detects registry modifications to the ProviderOrder or ProviderPath keys under NetworkProvider services, and file creation of DLLs in System32 by non-installer processes.
