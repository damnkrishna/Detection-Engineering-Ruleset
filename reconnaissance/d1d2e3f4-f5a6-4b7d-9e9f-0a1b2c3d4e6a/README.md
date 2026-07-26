# Phishing for Information from Compromised Internal Account (AN2073-Phishing-Internal)

## Metadata
- **Rule ID**: d1d2e3f4-f5a6-4b7d-9e9f-0a1b2c3d4e6a
- **Technique**: T1598

## Details
Detects internal emails querying for sensitive configurations or employee details, which may indicate a compromised mailbox. Note - Ingestion pipeline should normalize Unicode representations (NFKC) on incoming subjects to prevent evasion via multi-lingual or homoglyphic characters.
