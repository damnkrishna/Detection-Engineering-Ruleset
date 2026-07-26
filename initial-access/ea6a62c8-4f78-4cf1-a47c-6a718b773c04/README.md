# Exploit Public-Facing Application (AN0219)

## Description
Detects command-line interpreters or administrative utilities spawned by web server processes (e.g., IIS, Tomcat, Apache, Java web services) or outbound network connections initiated by them, suggesting successful exploitation or web shell deployment.

## Coverage
- Sysmon Event ID 1 (process_creation)
- Sysmon Event ID 3 (network_connection)
