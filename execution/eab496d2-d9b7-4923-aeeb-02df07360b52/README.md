# Suspicious Visual Basic Script Execution (AN0209)

## Description
Detects suspicious execution of wscript.exe or cscript.exe spawned by Microsoft Office applications or executing VBScripts from user-writable directories. Also detects the creation of Visual Basic script files inside user-writable temp folders, indicating staging for execution.

## Coverage
- Sysmon Event ID 1 (process_creation)
- Sysmon Event ID 11 (file_event)
