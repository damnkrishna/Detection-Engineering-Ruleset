# Anomalous HTTP Error Rate from Single Source (AN2069-Error-Spike)

## Metadata
- **Rule ID**: b7e3f1a2-c4d5-4e6f-9a0b-1c2d3e4f5a6b
- **Technique**: T1594

## Details
Detects a single source IP generating a high volume of HTTP 4xx or 5xx error responses in a short window, indicating directory brute-forcing (404s) or API parameter fuzzing (400/500 errors). Covers the fuzzing gap that AN2069 misses when tools target non-hardcoded paths or generate non-403 error codes. Note: SIEM-side aggregation required — count(http_status) by src_ip where http_status >= 400 > 50 in 1m.
