# AN0511 - Server Software Component: SQL Stored Procedures (T1505.001)

## Metadata
- **Rule ID**: AN0511
- **Technique**: T1505.001

## Details
Detects process execution originating from SQL Server involving dangerous stored procedures (xp_cmdshell, sp_OACreate), typically used for code execution or persistence.
