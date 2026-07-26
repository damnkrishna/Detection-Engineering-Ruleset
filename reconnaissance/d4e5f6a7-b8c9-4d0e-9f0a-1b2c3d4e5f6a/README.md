# Web Path Discovery in CDN Access Logs (AN2069-CDN-Logs)

## Metadata
- **Rule ID**: d4e5f6a7-b8c9-4d0e-9f0a-1b2c3d4e5f6a
- **Technique**: T1594

## Details
Detects web path discovery scans in CDN access logs (Cloudflare). Requires custom Cloudflare log ingestion pipeline and Sigma backend mapping. Note: SIEM-side aggregation (count(client_ip) by client_ip > 5 in 1m) is required before this generates actionable alerts.
