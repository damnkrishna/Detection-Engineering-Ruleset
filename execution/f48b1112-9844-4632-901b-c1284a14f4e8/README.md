# Suspicious Execution via Malicious Installer/Package Manager (AN0699)

## Metadata
- **Rule ID**: f48b1112-9844-4632-901b-c1284a14f4e8
- **Technique**: T1204.005

## Details
Detects the execution of pip, npm, or MSI installers followed by suspicious child processes (script interpreters) or writes to temporary user directories.
