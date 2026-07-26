# WinRM Remote Command Execution in Script Block (AN1313-B)

## Metadata
- **Rule ID**: 0f7dbf8f-b44e-48e2-8a49-ce44958a582e
- **Technique**: T1021.006

## Details
Detects PowerShell script block execution containing keywords or patterns indicating remote command invocation via WinRM (e.g. wsmprovhost, Enter-PSSession, Invoke-Command).
