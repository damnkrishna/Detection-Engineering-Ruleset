# LSA Password Filter DLL Registration and File Write (AN1303)

## Description
Detects registry modifications to the Notification Packages key used to load password filters in LSASS, and detects file creation of DLLs inside System32, filtering out trusted installers. This is associated with T1556.002.

## Coverage
- Sysmon Event ID 13 (registry_set)
- Sysmon Event ID 11 (file_event)
