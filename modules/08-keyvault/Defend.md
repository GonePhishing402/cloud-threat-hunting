# Defend - Module 08 (Key Vault Abuse)

## Defensive Controls

- Prefer Microsoft Entra-based authorization with least-privilege RBAC.
- Use private endpoints and network controls for vault access.
- Enforce soft-delete and purge protection.
- Enable and monitor Key Vault audit logs and Defender for Key Vault alerts.

## Key Vault Logging via Diagnostic Settings

### Why enable it

Key Vault audit telemetry is required to investigate who accessed secrets/keys, from where, and which operations succeeded or failed.

### How to enable (Azure portal)

1. Open the Key Vault resource.
2. Go to **Diagnostic settings** and select **Add diagnostic setting**.
3. Under category groups, enable **audit** and **allLogs** (or at minimum `AuditEvent`).
4. Select **Send to Log Analytics workspace** and choose your Sentinel workspace.
5. Save and validate ingestion.

### At-scale option

- Use built-in Azure Policy definitions to deploy Key Vault diagnostic settings to Log Analytics automatically.

## Key Vault Tables and Key Fields (Sentinel/Log Analytics)

### Primary tables

- `AZKVAuditLogs` (recommended Key Vault audit table)
- `AzureDiagnostics` (Key Vault `AuditEvent` category, multi-resource table)
- `AZKVPolicyEvaluationDetailsLogs` (policy evaluation details)
- `AzureActivity` (management-plane operations)

### Key investigation fields

- `TimeGenerated`: Event time (when)
- `_ResourceId`: Vault resource identifier
- `OperationName`: Operation performed (`SecretGet`, policy updates, etc.)
- `CallerIPAddress` or `callerIpAddress`: Request source IP
- `httpStatusCode_d` / `resultSignature`: HTTP result status
- `DurationMs` / `durationMs`: Request execution duration
- `requestUri_s` / `requestUri`: Requested URI path
- `identity` / identity claims: Calling principal context (user/SP/app)
- `CorrelationId` / `correlationId`: Cross-event correlation key

### Practical use

- Enumeration detection: unusual `SecretList` + `SecretGet` sequences.
- Privilege abuse detection: access-policy change then immediate secret access.
- Suspicious-source detection: key vault access from known bad/suspicious IP ranges.

## Defender for Key Vault Alerts (Defender for Cloud)

Defender for Key Vault provides threat detections for unusual and potentially harmful attempts to access or exploit Key Vault accounts.

### Alert families you should expect

- Suspicious source indicators:
  - `KV_SuspiciousIPAccess`
  - `KV_SuspiciousIPAccessDenied`
  - `KV_TORAccess`
- Behavioral anomalies:
  - `KV_OperationVolumeAnomaly`
  - `KV_UserAnomaly`
  - `KV_UserAppAnomaly`
  - `KV_AccountVolumeAnomaly`
- Access-control abuse patterns:
  - `KV_PutGetAnomaly` (policy change then secret query)
  - `KV_ListGetAnomaly` (suspicious listing and query pattern)

### Defender for Cloud operations note

- Enable the **Defender for Key Vault** plan at the subscription level in Defender for Cloud.
- Route/triage these alerts in Sentinel/SIEM and pivot into Key Vault audit logs for full scope analysis.

## Microsoft Learn References

- Enable Key Vault logging (diagnostic settings): https://learn.microsoft.com/azure/key-vault/general/howto-logging
- Key Vault logging overview and schema notes: https://learn.microsoft.com/azure/key-vault/general/logging
- Monitor Key Vault: https://learn.microsoft.com/azure/key-vault/general/monitor-key-vault
- Key Vault monitoring data reference: https://learn.microsoft.com/azure/key-vault/general/monitor-key-vault-reference
- Key Vault Log Analytics tables: https://learn.microsoft.com/azure/azure-monitor/reference/tables/microsoft-keyvault_vaults
- AzureDiagnostics table schema: https://learn.microsoft.com/azure/azure-monitor/reference/tables/azurediagnostics
- AZKVAuditLogs table schema: https://learn.microsoft.com/azure/azure-monitor/reference/tables/azkvauditlogs
- Defender for Key Vault overview: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-key-vault-introduction
- Enable Defender for Key Vault plan: https://learn.microsoft.com/azure/defender-for-cloud/tutorial-enable-key-vault-plan
- Azure Key Vault alerts reference: https://learn.microsoft.com/azure/defender-for-cloud/alerts-azure-key-vault
- Defender for Cloud policy reference (Key Vault plan): https://learn.microsoft.com/azure/defender-for-cloud/policy-reference#microsoft-defender-for-cloud-category
