# System Information Discovery (AN2083)

## Description
Detects command-line utilities extracting detailed system, patch, and OS information. Covers renamed binaries via OriginalFileName to resist trivial binary-rename evasion.

## Coverage
- Sysmon Event ID 1 (process_creation)
