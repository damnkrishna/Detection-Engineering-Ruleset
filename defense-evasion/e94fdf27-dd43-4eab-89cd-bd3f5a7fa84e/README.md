# PowerShell Silent Error Suppression for Evasion (AN0182-A)

## Metadata
- **Rule ID**: d11c7e85-9b25-41be-a73d-7185b940268b
- **UUID**: e94fdf27-dd43-4eab-89cd-bd3f5a7fa84e
- **Rule Type**: Custom Sigma Rule / OCSF Normalized
- **Analytic ID**: AN0182
- **Detection ID**: DET0067
- **Technique**: T1564.011
- **Author**: Krishna Gupta

## Description
Detects PowerShell execution with error action preference set to SilentlyContinue or Ignore in script block logs, used by adversaries to suppress error output and execute commands without alerting users or detection tools.

## Logs
- `benign_1.jsonl`: Contains true negative telemetry for benign activity.
- `true_positive_1.jsonl`: Contains true positive telemetry verifying the rule logic.
