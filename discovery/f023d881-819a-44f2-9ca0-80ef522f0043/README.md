# Remote System Discovery (AN2079)

## Description
Detects command-line utilities querying the domain for computer objects or domain controllers. Covers renamed binaries via OriginalFileName to resist trivial binary-rename evasion.

## Coverage
- Sysmon Event ID 1 (process_creation)
