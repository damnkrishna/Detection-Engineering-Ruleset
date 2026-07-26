# Windows Management Instrumentation (AN1031)

## Description
Detects command-line shells or script hosts spawned as child processes of the WMI Provider Host, indicating WMI-based code execution. Also detects command-line execution of wmic.exe initiating process creations or altering shadow copies.

## Coverage
- Sysmon Event ID 1 (process_creation)
