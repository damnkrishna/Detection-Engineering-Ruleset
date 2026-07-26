# Print Spooler Service Spawning Suspicious Child Process (AN2118)

## Metadata
- **Rule ID**: f1a2b3c4-e5f6-7a8b-9c0d-1e2f3a4b5d99
- **Technique**: T1212

## Details
Detects the Windows Print Spooler service (spoolsv.exe) spawning unusual child processes such as command shells or discovery tools. This behavior is strongly associated with PrintNightmare (CVE-2021-1675/CVE-2021-34527) and similar spooler exploitation.
