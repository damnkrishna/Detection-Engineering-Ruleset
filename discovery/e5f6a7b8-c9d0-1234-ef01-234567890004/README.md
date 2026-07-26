# Windows Event Log Enumeration (AN2091)

## Metadata
- **Rule ID**: 4d57fab8-52be-4340-b3cf-206751ae8e30
- **UUID**: e5f6a7b8-c9d0-1234-ef01-234567890004
- **Rule Type**: Custom Sigma Rule / OCSF Normalized
- **Analytic ID**: AN2091
- **Detection ID**: DET0948
- **Technique**: T1654
- **Author**: Krishna Gupta

## Description
Detects command-line utilities enumerating or exporting Windows event logs, used by attackers to assess security tooling and forensic visibility. Covers renamed binaries via OriginalFileName to resist trivial binary-rename evasion.

## Logs
- `benign_1.jsonl`: Contains true negative telemetry for benign activity.
- `true_positive_1.jsonl`: Contains true positive telemetry verifying the rule logic.
