# System Network Connections Discovery (AN2081)

## Description
Detects command-line execution querying active network sessions or mapped drives. Covers renamed net.exe via OriginalFileName to resist trivial binary-rename evasion.

## Coverage
- Sysmon Event ID 1 (process_creation)
