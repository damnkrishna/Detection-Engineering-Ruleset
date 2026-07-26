# Hardware Supply Chain - Firmware Flashing (AN1035)

## Description
Detects the execution of known firmware/BIOS flashing tools, which may indicate unauthorized BIOS/firmware modification. Also detects the loading of vulnerable or low-level firmware helper drivers commonly utilized by BIOS flash utilities.

## Coverage
- Sysmon Event ID 1 (process_creation)
- Sysmon Event ID 6 (driver_activity)
