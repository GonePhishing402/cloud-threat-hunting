# Defend - Module 04 (Storage Abuse)

## Defensive Controls

- Prefer Microsoft Entra authorization with managed identities.
- Disallow Shared Key authorization whenever possible.
- Use user delegation SAS with narrow scope and short expiry.
- Apply private networking and strict firewall/network ACL controls.

## Storage Logging via Diagnostic Settings

### Why enable it

Storage data-plane and management telemetry are required to investigate key listing, SAS misuse, suspicious read patterns, and exfiltration behavior.

### How to enable (Azure portal)

1. Open the Storage account.
2. Go to **Monitoring > Diagnostic settings**.
3. Add a new diagnostic setting.
4. Enable **Send to Log Analytics workspace** (your Sentinel workspace).
5. Select log categories:
	- `StorageRead`
	- `StorageWrite`
	- `StorageDelete`
6. Also export relevant metrics (such as `Transaction`) if needed for volume/context correlation.
7. Save and validate ingestion in Log Analytics.

### Scope reminder

- For a storage account, configure diagnostics on the parent resource and service child resources (blob/file/queue/table) so all relevant logs are available.

## Storage Tables and Key Fields (Sentinel/Log Analytics)

### Primary tables

- `StorageBlobLogs` (Blob + ADLS Gen2 data-plane operations)
- `StorageFileLogs` (Azure Files data-plane operations)
- `StorageQueueLogs` (Queue operations)
- `StorageTableLogs` (Table service operations)
- `AzureActivity` (management-plane actions like policy/key/config changes)

### Key investigation fields

Use these fields first for triage and timeline reconstruction (field names are documented in Azure Monitor table references):

- `TimeGenerated`: Event time (when)
- `AccountName`: Storage account targeted
- `OperationName`: Action performed (what)
- `AuthenticationType`: Auth path (`OAuth`, `SAS`, `AccountKey`, etc.)
- `CallerIpAddress`: Source IP/port
- `RequesterObjectId`: Calling Entra object ID for OAuth-authenticated requests (who)
- `Uri` or `ObjectKey`: Target object/container path
- `StatusCode` and `StatusText`: Operation outcome
- `UserAgentHeader`: Calling tool/client fingerprint
- `CorrelationId`: Cross-resource activity stitching

### Practical use

- Exfiltration: high-volume `GetBlob`/read operations with unusual `CallerIpAddress`.
- SAS abuse: `AuthenticationType == "SAS"` with unusual source and operation mix.
- Identity-backed abuse: suspicious `RequesterObjectId` + `OperationName` combinations.

## Detection Objectives

- Detect `listKeys` and high-risk key operations.
- Detect unusual SAS usage and high-volume reads.
- Detect storage reconnaissance and extraction patterns.

## Defender for Storage Alerts (Defender for Cloud)

Defender for Storage provides agentless threat detection and alerting for Blob, Files, and ADLS Gen2 scenarios. It can detect many storage threats even without customer-enabled diagnostic logs, because it analyzes service telemetry directly.

### Alert families you should expect

- Malicious content uploads/downloads:
	- `Storage.Blob_AM.MalwareFound`
	- `Storage.File_AM.MalwareFound`
	- `Storage.Blob_MalwareDownload`
- Suspicious SAS token activity:
	- unusual external SAS use
	- overly permissive SAS used externally or for unusual operations
- Suspicious access and reconnaissance:
	- unusual data exploration
	- unusual unauthenticated public access (especially on sensitive containers)
	- access from suspicious IPs, Tor exit nodes, suspicious applications
- Data impact/exfiltration patterns:
	- unusual data extraction volume/count
	- unusual deletions
	- sensitive container ACL changes to public access

### Defender for Cloud operations note

- Route Defender for Cloud alerts to Sentinel/SIEM for SOC workflows and automation.
- Treat storage alerts as high-priority pivots into `StorageBlobLogs`/related tables for deeper incident scoping.

## Microsoft Learn References

- Storage authorization guidance: https://learn.microsoft.com/azure/storage/common/authorize-data-access
- Blob security best practices: https://learn.microsoft.com/azure/well-architected/service-guides/azure-blob-storage
- Diagnostic settings overview: https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings
- Storage monitoring scenarios (audit fields and examples): https://learn.microsoft.com/azure/storage/blobs/blob-storage-monitoring-scenarios#audit-account-activity
- Azure Blob Storage monitoring reference: https://learn.microsoft.com/azure/storage/blobs/monitor-blob-storage-reference
- Azure Monitor table index (Storage*Logs tables): https://learn.microsoft.com/azure/azure-monitor/reference/tables-index#resource-log---log-analytics-tables
- StorageBlobLogs table schema: https://learn.microsoft.com/azure/azure-monitor/reference/tables/storagebloblogs
- StorageFileLogs table schema: https://learn.microsoft.com/azure/azure-monitor/reference/tables/storagefilelogs
- StorageQueueLogs table schema: https://learn.microsoft.com/azure/azure-monitor/reference/tables/storagequeuelogs
- StorageTableLogs table schema: https://learn.microsoft.com/azure/azure-monitor/reference/tables/storagetablelogs
- Defender for Storage overview: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-storage-introduction
- Defender for Storage threats and alert scenarios: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-storage-threats-alerts
- Azure Storage alerts reference (Defender for Cloud): https://learn.microsoft.com/azure/defender-for-cloud/alerts-azure-storage
- Deploy/enable Defender for Storage: https://learn.microsoft.com/azure/defender-for-cloud/tutorial-enable-storage-plan
