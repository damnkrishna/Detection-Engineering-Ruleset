# Query Registry (AN2077)

## Description
Detects command-line queries of the Windows Registry for LSA providers, Autoruns, or SAM information. Covers renamed reg.exe via OriginalFileName to resist trivial binary-rename evasion.

## Coverage
- Sysmon Event ID 1 (process_creation)
