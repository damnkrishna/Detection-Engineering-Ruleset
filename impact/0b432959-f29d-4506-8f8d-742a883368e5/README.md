# Windows Resource Exhaustion Diagnosis Event (AN1012-A)

## Metadata
- **Rule ID**: 0b432959-f29d-4506-8f8d-742a883368e5
- **Technique**: T1499.001

## Details
Detects Windows Diagnostic-Performance or System Event ID 2004 logs capturing critical virtual memory exhaustion. This rule should be aggregated in the SIEM layer to count loop patterns.
