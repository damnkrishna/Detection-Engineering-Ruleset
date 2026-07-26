# Exclusive Control via Service Termination or Self-Patching (AN0045)

## Metadata
- **Rule ID**: a3014d19-9720-47d6-ab4c-43137fde1d05
- **UUID**: e7cb71a0-3ef2-4d2c-bc7d-a5df8c2ba310
- **Rule Type**: Custom Sigma Rule / OCSF Normalized
- **Analytic ID**: AN0045
- **Detection ID**: DET0015
- **Technique**: T1668
- **Author**: Krishna Gupta

## Description
Detects adversarial establishment of exclusive control by stopping or patching vulnerable services (using sc stop, net stop, or taskkill) to prevent competitor access to the compromised host.

## Logs
- `benign_1.jsonl`: Contains true negative telemetry for benign activity.
- `true_positive_1.jsonl`: Contains true positive telemetry verifying the rule logic.
