# Module 07 — Logging Enablement for Azure Threat Hunting

## Objective

Ensure all necessary Azure diagnostic settings are enabled to support threat hunting across every module in this training. Students learn to identify logging gaps, configure diagnostic settings, and estimate ingestion costs.

## Duration

~2 hours (lecture + configuration lab)

> **Delivery Note:** This module should be delivered EARLY in the engagement (Day 1, after Module 00). It is a prerequisite for all hunting modules.

## Why This Module Matters

Without proper logging, threat hunting is impossible. This module ensures students understand:
- What data sources exist in Azure
- Which logs are enabled by default vs. require explicit configuration
- How to route logs to Microsoft Sentinel (Log Analytics)
- How to estimate and manage ingestion costs

## Logging Coverage Matrix

| Data Source | Sentinel Table | Default? | Required For |
|---|---|---|---|
| Azure AD Sign-in Logs | `SigninLogs` | No — requires diagnostic setting | Modules 01, 02 |
| Azure AD Non-Interactive | `AADNonInteractiveUserSignInLogs` | No — requires diagnostic setting | Modules 01, 02, 05 |
| Azure AD Audit Logs | `AuditLogs` | No — requires diagnostic setting | Modules 01, 05 |
| Azure AD SP Sign-in Logs | `AADServicePrincipalSignInLogs` | No — requires diagnostic setting | Module 05 |
| Azure AD MI Sign-in Logs | `AADManagedIdentitySignInLogs` | No — requires diagnostic setting | Modules 03, 05 |
| Azure Activity Logs | `AzureActivity` | No — per subscription | Modules 03, 04, 05 |
| Storage Blob Logs | `StorageBlobLogs` | No — per storage account | Module 04 |
| Key Vault Audit Logs | `AzureDiagnostics` (KeyVault) | No — per Key Vault | Module 04 |
| Logic App Runtime Logs | `AzureDiagnostics` (Logic) | No — per Logic App | Module 03 |
| Microsoft Graph Activity | `MicrosoftGraphActivityLogs` | No — requires configuration | Module 02 |
| Office 365 Logs | `OfficeActivity` | Via Sentinel connector | Module 01 |

## Configuration Guide

### 1. Azure AD Diagnostic Settings

Route Azure AD logs to your Log Analytics workspace:

**Azure Portal Path:** Azure Active Directory > Diagnostic settings > Add diagnostic setting

**Categories to Enable:**
- ✅ SignInLogs
- ✅ NonInteractiveUserSignInLogs
- ✅ ServicePrincipalSignInLogs
- ✅ ManagedIdentitySignInLogs
- ✅ AuditLogs
- ✅ RiskyUsers
- ✅ UserRiskEvents
- ✅ RiskyServicePrincipals (if available)

**Bicep Template:**
```bicep
resource aadDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'aad-to-sentinel'
  scope: tenant()
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      { category: 'SignInLogs', enabled: true }
      { category: 'NonInteractiveUserSignInLogs', enabled: true }
      { category: 'ServicePrincipalSignInLogs', enabled: true }
      { category: 'ManagedIdentitySignInLogs', enabled: true }
      { category: 'AuditLogs', enabled: true }
      { category: 'RiskyUsers', enabled: true }
      { category: 'UserRiskEvents', enabled: true }
    ]
  }
}
```

### 2. Azure Activity Log (Per Subscription)

**Azure Portal:** Subscription > Activity log > Diagnostic settings

```bicep
resource activityLogDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'activity-to-sentinel'
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      { category: 'Administrative', enabled: true }
      { category: 'Security', enabled: true }
      { category: 'Alert', enabled: true }
      { category: 'Policy', enabled: true }
    ]
  }
}
```

### 3. Storage Account Blob Logs

```bicep
resource storageDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'storage-blob-to-sentinel'
  scope: storageAccount::blobService
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      { category: 'StorageRead', enabled: true }
      { category: 'StorageWrite', enabled: true }
      { category: 'StorageDelete', enabled: true }
    ]
    metrics: [
      { category: 'Transaction', enabled: true }
    ]
  }
}
```

### 4. Key Vault Diagnostic Logs

```bicep
resource kvDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'keyvault-to-sentinel'
  scope: keyVault
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      { category: 'AuditEvent', enabled: true }
    ]
    metrics: [
      { category: 'AllMetrics', enabled: true }
    ]
  }
}
```

### 5. Logic App Runtime Logs

```bicep
resource logicAppDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'logicapp-to-sentinel'
  scope: logicApp
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      { category: 'WorkflowRuntime', enabled: true }
    ]
    metrics: [
      { category: 'AllMetrics', enabled: true }
    ]
  }
}
```

## Ingestion Cost Estimation

### Approximate Daily Volumes (500-user organization)

| Log Source | Est. Daily Volume | Est. Monthly Cost (Pay-As-You-Go) |
|---|---|---|
| SigninLogs | ~500 MB | ~$75 |
| NonInteractiveUserSignInLogs | ~2 GB | ~$300 |
| AuditLogs | ~100 MB | ~$15 |
| ServicePrincipalSignInLogs | ~200 MB | ~$30 |
| AzureActivity | ~100 MB/subscription | ~$15/sub |
| StorageBlobLogs | Varies widely | Depends on access volume |
| Key Vault Logs | ~50 MB | ~$8 |
| Logic App Logs | ~50 MB | ~$8 |

> Costs based on $4.30/GB Sentinel ingestion pricing. Commitment tiers reduce costs significantly.

### Cost Optimization Strategies
- **Basic Logs tier**: Use for high-volume, low-query tables (StorageBlobLogs, NonInteractiveUserSignInLogs)
- **Data Collection Rules (DCRs)**: Filter and transform data before ingestion
- **Commitment tiers**: 100 GB/day commitment tier saves ~50% vs. pay-as-you-go
- **Retention policies**: Set interactive retention to 90 days, archive to 2 years for compliance
- **Table-level configuration**: Customize ingestion and retention per table

## CTFd Challenges

| # | Title | Difficulty | Description |
|---|---|---|---|
| 1 | Log Check | Easy | Query each Sentinel table and identify which ones are empty (no logs configured) |
| 2 | Blind Spot | Medium | Given a hunt scenario from Module 01, identify which logs are missing to complete the investigation |
| 3 | Cost Calculator | Medium | Estimate the monthly ingestion cost to enable full logging coverage for the lab environment |

## Validation Query

After enabling all diagnostic settings, run this validation:
```kql
union withsource=TableName *
| where TimeGenerated > ago(1h)
| summarize RowCount = count(), LastEvent = max(TimeGenerated) by TableName
| order by TableName asc
```

## References

- [Azure Monitor Diagnostic Settings](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings)
- [Microsoft Sentinel Data Connectors](https://learn.microsoft.com/en-us/azure/sentinel/connect-data-sources)
- [Sentinel Pricing](https://azure.microsoft.com/en-us/pricing/details/microsoft-sentinel/)
- [Basic Logs in Azure Monitor](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/basic-logs-configure)
