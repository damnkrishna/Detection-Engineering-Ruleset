# Inter-Process Communication (AN1357)

## Description
Detects Sysmon Event ID 17 named pipe creation events pointing to post-exploitation frameworks or anomalous prefixes. Also detects command-line execution of regsvr32.exe or mshta.exe executing COM scripts.

## Coverage
- Sysmon Event ID 17 (pipe_created)
- Sysmon Event ID 1 (process_creation)
