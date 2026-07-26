# Account Discovery (AN2085)

## Description
Detects command-line execution of net user, net accounts, or dsquery user to enumerate accounts. Covers renamed binaries via OriginalFileName to resist trivial binary-rename evasion.

## Coverage
- Sysmon Event ID 1 (process_creation)
