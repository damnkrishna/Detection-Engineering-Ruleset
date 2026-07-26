# RDP Session Hijacking (AN0216)

## Description
Detects RDP session hijacking via tscon.exe executed under SYSTEM context or via sc.exe creating a service with tscon in the binary path. Also detects service installation pointing to tscon.exe for session hijacking by monitoring System Event ID 7045.

## Coverage
- Sysmon Event ID 1 (process_creation)
- Windows System Log Event ID 7045 (system)
