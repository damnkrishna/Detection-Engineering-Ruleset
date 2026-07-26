# Native API (AN1465)

## Description
Detects processes loading critical system libraries from non-standard directories to bypass API hooking engines. Also detects user-space processes requesting high-privilege write or full control memory access handles targeting standard system processes.

## Coverage
- Sysmon Event ID 7 (image_load)
- Sysmon Event ID 10 (process_access)
