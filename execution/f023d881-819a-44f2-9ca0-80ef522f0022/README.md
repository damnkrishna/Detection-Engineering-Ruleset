# User Execution (AN1314)

## Description
Detects command shells or administrative LOLBINs spawned directly by Office or PDF viewer parent processes. Also detects command shells or scripting engines launched directly by archive managers.

## Coverage
- Sysmon Event ID 1 (process_creation)
