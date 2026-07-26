# Inter-Process Communication: Dynamic Data Exchange (AN1393)

## Description
Detects Office binaries launching cmd/powershell shells, suggesting active DDE code execution. Also detects registry edits enabling AllowDDE or overriding DDE protection flags.

## Coverage
- Sysmon Event ID 1 (process_creation)
- Sysmon Event ID 13 (registry_set)
