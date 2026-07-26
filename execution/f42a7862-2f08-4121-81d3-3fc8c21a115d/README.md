# Suspicious JavaScript Execution via WSH (AN0733)

## Metadata
- **Rule ID**: f42a7862-2f08-4121-81d3-3fc8c21a115d
- **Technique**: T1059.007

## Details
Detects JavaScript execution through wscript.exe, cscript.exe, or mshta.exe, particularly when spawned from Office macros or abnormal user paths.
