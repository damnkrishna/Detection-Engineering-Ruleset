# Internal Spearphishing via Scripting (AN0147)

## Description
Detects command-line interpreters, scripting hosts, or proxy executables initiating direct outbound TCP connections to mail gateway ports (25, 465, 587), suggesting automated internal spearphishing or mail worm propagation. Also detects PowerShell script block execution invoking SMTP client objects or mail message cmdlets to send emails.

## Coverage
- Sysmon Event ID 3 (network_connection)
- PowerShell Event ID 4104 (ps_script)
