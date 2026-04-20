# Module 04 — Storage Abuse in Azure

## Objective

Hunt for unauthorized access to Azure Storage accounts, including storage key extraction, SAS token abuse, and data exfiltration. Students learn to correlate management plane and data plane logs to trace full attack chains.

## Duration

~3 hours (lecture + hands-on labs)

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Unsecured Credentials | T1552 | Credential Access |
| Data from Cloud Storage | T1530 | Collection |
| Account Manipulation | T1098 | Persistence |
| Exfiltration Over Web Service | T1567 | Exfiltration |

## Sentinel Tables

- `AzureActivity` — Management plane operations (key regeneration, policy changes)
- `StorageBlobLogs` / `StorageQueueLogs` / `StorageTableLogs` — Data plane access logs
- `AuditLogs` — Identity and permission changes that affect storage access

## Attack Narratives

### 1. Storage Account Key Extraction

**Attack Flow:**
1. Attacker with Reader+ access on a storage account lists the access keys
2. Access keys provide full control over the storage account (both data and management)
3. Attacker uses keys from external infrastructure to access/exfiltrate blob data
4. Keys don't expire — persistent access until rotated

**Key Indicators:**
- `AzureActivity` with `OperationNameValue == "Microsoft.Storage/storageAccounts/listKeys/action"` from unusual callers
- Data plane access (StorageBlobLogs) from IPs different than management plane
- High volume blob reads or full container enumeration
- Access key usage from non-corporate IPs

### 2. SAS Token Generation and Abuse

**Attack Flow:**
1. Attacker generates SAS (Shared Access Signature) tokens using stolen account keys
2. SAS tokens can be scoped to specific containers/blobs with time-limited access
3. Tokens are shared externally — anyone with the token can access the data
4. Service SAS, Account SAS, and User Delegation SAS have different risk profiles

**Key Indicators:**
- SAS token generation events in AzureActivity
- StorageBlobLogs showing `AuthenticationType == "SAS"` from external IPs
- Unusual data transfer volumes using SAS-authenticated requests
- SAS tokens with overly broad permissions or long expiry times

## Hunt Playbooks

### Playbook 1: Storage Key Listing Detection
```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue == "Microsoft.Storage/storageAccounts/listKeys/action"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress, ResourceGroup, 
    StorageAccount = tostring(split(_ResourceId, "/")[-1])
| order by TimeGenerated desc
```

### Playbook 2: Anomalous Blob Access Patterns
```kql
StorageBlobLogs
| where TimeGenerated > ago(7d)
| where StatusCode == 200
| where OperationType in ("GetBlob", "GetBlobProperties", "ListBlobs")
| summarize 
    ReadCount = count(),
    DataTransferMB = sum(ResponseBodySize) / 1048576.0,
    DistinctBlobs = dcount(ObjectKey),
    DistinctIPs = dcount(CallerIpAddress),
    IPs = make_set(CallerIpAddress, 10)
    by AccountName, AuthenticationType, bin(TimeGenerated, 1h)
| where ReadCount > 100 or DataTransferMB > 500
| order by DataTransferMB desc
```

### Playbook 3: SAS Token Usage from External IPs
```kql
StorageBlobLogs
| where TimeGenerated > ago(7d)
| where AuthenticationType == "SAS"
| where StatusCode == 200
| extend IsPrivateIP = CallerIpAddress matches regex @"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
| where not(IsPrivateIP)
| summarize 
    AccessCount = count(),
    DataMB = sum(ResponseBodySize) / 1048576.0,
    Operations = make_set(OperationType),
    Containers = make_set(tostring(split(ObjectKey, "/")[1]))
    by AccountName, CallerIpAddress, bin(TimeGenerated, 1h)
| order by DataMB desc
```

## CTFd Challenges

| # | Title | Difficulty | Description |
|---|---|---|---|
| 1 | Key Collector | Easy | Identify who listed storage account keys from a non-corporate IP |
| 2 | SAS Leak | Medium | Find the SAS-authenticated blob access from an external IP and calculate total data exfiltrated |
| 3 | Blob Recon | Medium | Detect suspicious blob/container enumeration before exfiltration |
| 4 | Token Trail | Hard | Trace the full path of a suspicious SAS token from creation to data access |
| 5 | Data Heist | Hard | Reconstruct the full storage exfiltration: key listing -> SAS generation -> data download |

## Hardening

### Storage Accounts
- **Disable shared key access**: Use Azure AD authentication only (`AllowSharedKeyAccess = false`)
- **Private endpoints**: Restrict storage access to VNet-connected resources
- **SAS policy**: Use stored access policies; set short expiration times; prefer User Delegation SAS over Account SAS
- **Storage account firewall**: Restrict to known VNets and IPs
- **Enable logging**: StorageBlobLogs, StorageQueueLogs to Log Analytics workspace
- **Key rotation**: Automate key rotation; alert on manual `listKeys` operations

> Key Vault content moved to Module 08 (`modules/08-keyvault`).
