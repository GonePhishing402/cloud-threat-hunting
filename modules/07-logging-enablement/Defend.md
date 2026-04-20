# Defend - Module 07 (Logging Enablement)

## Defensive Goal

Guarantee that critical identity, control plane, and data plane logs are consistently ingested into the Sentinel workspace used for hunting and detection.

## Logging Defense Priorities

1. Enable Entra sign-in, non-interactive sign-in, service principal sign-in, and audit logs.
2. Enable Azure Activity diagnostics per subscription.
3. Enable storage, Key Vault, and Logic App diagnostics on scoped resources.
4. Validate connector health and data freshness in Sentinel.

## Operations Guidance

- Use policy-driven rollout for large scopes where possible.
- Track connector status and last-ingested timestamps.
- Keep a baseline query pack to validate table population daily.

## Microsoft Learn References

- Connect via diagnostic settings: https://learn.microsoft.com/azure/sentinel/connect-services-diagnostic-setting-based
- Data collection best practices: https://learn.microsoft.com/azure/sentinel/best-practices-data
- Prioritize data connectors: https://learn.microsoft.com/azure/sentinel/prioritize-data-connectors
