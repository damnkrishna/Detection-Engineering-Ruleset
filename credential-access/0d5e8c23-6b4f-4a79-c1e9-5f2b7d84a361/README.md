# Browser Cookie Database Access by Non-Browser Process (AN2107)

## Metadata
- **Rule ID**: 0d5e8c23-6b4f-4a79-c1e9-5f2b7d84a361
- **Technique**: T1539

## Details
Detects processes other than browsers reading SQLite cookie databases from Chrome, Edge, or Firefox profile directories. Used by attackers to steal authenticated session tokens without re-authenticating.
