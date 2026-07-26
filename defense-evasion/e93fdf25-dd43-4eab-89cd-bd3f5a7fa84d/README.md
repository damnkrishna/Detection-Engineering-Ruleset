# Persistence Artifact Removal for Anti-Forensics (AN0113-A)

## Metadata
- **Rule ID**: 13284a96-dced-4897-adda-dbb8276b9237
- **UUID**: e93fdf25-dd43-4eab-89cd-bd3f5a7fa84d
- **Rule Type**: Custom Sigma Rule / OCSF Normalized
- **Analytic ID**: AN0113
- **Detection ID**: DET0040
- **Technique**: T1070.009
- **Author**: Krishna Gupta

## Description
Detects adversary activity removing persistence artifacts such as scheduled tasks, services, or registry run keys using sc delete, schtasks /delete, or reg delete — indicative of anti-forensic cleanup.

## Logs
- `benign_1.jsonl`: Contains true negative telemetry for benign activity.
- `true_positive_1.jsonl`: Contains true positive telemetry verifying the rule logic.
