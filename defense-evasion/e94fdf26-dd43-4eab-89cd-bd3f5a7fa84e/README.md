# Verclsid LOLBin Abuse for COM Object Execution (AN0118-A)

## Metadata
- **Rule ID**: 59534fdd-8afd-4447-9295-f743fb37c7d6
- **UUID**: e94fdf26-dd43-4eab-89cd-bd3f5a7fa84e
- **Rule Type**: Custom Sigma Rule / OCSF Normalized
- **Analytic ID**: AN0118
- **Detection ID**: DET0042
- **Technique**: T1218.012
- **Author**: Krishna Gupta

## Description
Detects abuse of verclsid.exe (a signed Windows Shell binary) to execute arbitrary COM objects via CLSID arguments, which may load malicious scriptlets or DLLs.

## Logs
- `benign_1.jsonl`: Contains true negative telemetry for benign activity.
- `true_positive_1.jsonl`: Contains true positive telemetry verifying the rule logic.
