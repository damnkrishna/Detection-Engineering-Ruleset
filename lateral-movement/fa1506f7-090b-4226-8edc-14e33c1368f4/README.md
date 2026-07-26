# Runas with Netonly Flag (AN0954-B)

## Metadata
- **Rule ID**: fa1506f7-090b-4226-8edc-14e33c1368f4
- **Technique**: T1550

## Details
Detects the execution of runas.exe with the /netonly argument, which is commonly used by adversaries for outbound authentication using alternate credentials (e.g. Pass-the-Hash or Pass-the-Ticket).
