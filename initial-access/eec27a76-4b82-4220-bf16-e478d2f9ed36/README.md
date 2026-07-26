# Exploit Public-Facing Application (AN0219)

## Description
Detects command-line interpreters or administrative utilities spawned by web server processes (e.g., IIS, Tomcat, Apache, Java web services). Also detects outbound network connections initiated by web server processes to non-local IP addresses.

## Coverage
- Sysmon Event ID 1 (process_creation)
- Sysmon Event ID 3 (network_connection)
