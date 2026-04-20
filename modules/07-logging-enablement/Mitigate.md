# Mitigate - Module 07 (Logging Enablement)

## Logging Gap Mitigation Playbook

1. Identify empty/low-volume critical tables in Sentinel.
2. Enable missing diagnostic settings for affected services.
3. Apply policy-based remediation for at-scale resources.
4. Revalidate data flow and connector status after changes.

## Rapid Fix Targets

- `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`
- `AzureActivity`
- `StorageBlobLogs`
- `AzureDiagnostics` for Key Vault and Logic Apps

## Sustainment Controls

- Add periodic data freshness checks.
- Alert on connector disconnect states or sudden ingestion drops.
- Tie logging configuration checks to change management and IaC reviews.

## Microsoft Learn References

- Diagnostic settings connectors for Sentinel: https://learn.microsoft.com/azure/sentinel/connect-services-diagnostic-setting-based
- Azure Monitor diagnostic settings: https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings
- Turn on Sentinel health monitoring: https://learn.microsoft.com/azure/sentinel/enable-monitoring
