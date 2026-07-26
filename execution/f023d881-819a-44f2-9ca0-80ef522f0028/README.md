# Command and Scripting Interpreter (AN1428)

## Description
Detects command-line execution of wscript.exe or cscript.exe with parameters executing vbscript or jscript. Also detects cscript.exe or wscript.exe processes spawned by unusual parent processes.

## Coverage
- Sysmon Event ID 1 (process_creation)
