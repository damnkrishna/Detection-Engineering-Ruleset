# Suspicious Remote Thread Creation (PE Injection) (AN0297)

## Metadata
- **Rule ID**: f43e2a1b-7890-4c12-b345-6d7e8f9a0b1c
- **Technique**: T1055.002

## Details
Detects PE injection where a process initiates a new thread (CreateRemoteThread) in another live process, executing injected code.
