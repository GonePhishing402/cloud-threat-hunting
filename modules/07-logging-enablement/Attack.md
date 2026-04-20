# Attack - Module 07 (Logging Enablement)

## Attack Pattern: Logging Blind Spots

Attackers benefit from missing or incomplete telemetry. Common abuse patterns include:

1. Performing actions in services without diagnostic settings enabled.
2. Leveraging data-plane paths that are not ingested to Sentinel.
3. Sustaining persistence while defenders cannot correlate events end to end.

## Adversary Advantage

- Lower chance of detection for credential abuse and data exfiltration.
- Delayed incident response due to missing context and broken timelines.
- Easier evasion when service-level logs are inconsistent.

## Required Visibility Domains

- Entra sign-in and audit logs.
- Azure Activity logs.
- Service-specific diagnostics (Storage, Key Vault, Logic Apps).

## Microsoft Learn References

- Diagnostic settings-based Sentinel connectors: https://learn.microsoft.com/azure/sentinel/connect-services-diagnostic-setting-based
- Diagnostic settings in Azure Monitor: https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings
- Sentinel data connector reference: https://learn.microsoft.com/azure/sentinel/data-connectors-reference
