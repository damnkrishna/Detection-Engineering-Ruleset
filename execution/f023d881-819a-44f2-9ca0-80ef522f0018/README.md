# System Services: Service Execution (AN1185)

## Description
Detects non-standard binaries spawned directly by services.exe, suggesting malicious service executions. Also detects command-line parameters utilizing sc.exe or net.exe to create or modify service binaries.

## Coverage
- Sysmon Event ID 1 (process_creation)
