## Slide 1: Azure Storage Abuse

Module 04 — Storage Key Extraction, SAS Token Abuse, and Data Exfiltration

**Speaker Notes:**
Welcome to Module 04. We move from Logic Apps to Azure Storage — one of the most data-rich attack surfaces in Azure. Attackers target storage account keys and SAS tokens to access blobs, files, queues, and tables. The critical challenge is that storage data-plane access requires separate diagnostic logging (StorageBlobLogs) beyond the default AzureActivity control plane logs. This module teaches you to detect key extraction, anomalous blob access, and SAS token abuse.

## Slide 2: Agenda

- Module Objective and MITRE ATT&CK Mapping
- Storage Attack Surface Overview
- Attack Techniques: Key Extraction, SAS Abuse, Blob Recon
- Enabling Storage Diagnostic Logging
- Key Sentinel Tables and Fields
- KQL Detection Queries
- Defender for Storage Alerts
- Incident Response
- Hardening Controls

**Speaker Notes:**
This module covers the full storage attack chain: key extraction via listKeys, SAS token generation and abuse, and blob reconnaissance and exfiltration. A critical prerequisite is enabling storage diagnostic logging — without it, you have no visibility into data-plane operations. We'll cover the detection tables, key fields, and three KQL queries that detect the most common storage abuse patterns. We finish with Defender for Storage built-in alerts and hardening recommendations including the transition to Entra ID authentication.

## Slide 3: Objective and MITRE Mapping

!layout: Title and Content

**Objective:** Hunt for unauthorized storage access, key extraction, and SAS token abuse in Azure Storage. Detect data exfiltration patterns in StorageBlobLogs.

| Technique | ID | Tactic |
|---|---|---|
| Unsecured Credentials | T1552 | Credential Access |
| Data from Cloud Storage | T1530 | Collection |
| Account Manipulation | T1098 | Persistence |
| Exfiltration Over Web Service | T1567 | Exfiltration |

**Speaker Notes:**
Storage abuse maps to four MITRE techniques. T1552 covers the initial key extraction — storage account keys are unsecured credentials that provide full data-plane access. T1530 covers the collection phase where the attacker reads blobs and files. T1098 covers persistence via SAS token generation. T1567 covers the exfiltration of data to attacker-controlled infrastructure.

## Slide 4: Storage Attack Surface

!layout: Title and Content

**Two planes of access:**
- **Control Plane (AzureActivity):** List storage accounts, list keys, manage RBAC — always logged
- **Data Plane (StorageBlobLogs):** Read/write blobs, list containers — requires diagnostic logging

**Three attack patterns:**
- **Storage Account Key Extraction:** Keys provide full control, never expire, persist until rotated
- **SAS Token Generation and Abuse:** Scoped tokens generated from stolen keys, shareable externally
- **Blob Reconnaissance and Exfiltration:** Enumerate containers, download sensitive blobs at scale

**Critical gap:** Many organizations have AzureActivity enabled but NOT StorageBlobLogs — they can see who listed keys but NOT what data was accessed.

**Speaker Notes:**
The two-plane distinction is critical. AzureActivity captures control plane operations — who listed keys, who changed RBAC. But it does NOT capture data plane operations — who read which blobs, how much data was downloaded. StorageBlobLogs captures the data plane, but it requires explicit diagnostic settings on each storage account. Without it, you're blind to the actual data exfiltration. This is the most common visibility gap in Azure storage security. Ask students: how many have StorageBlobLogs enabled on their storage accounts?

## Slide 5: Enabling Storage Diagnostic Logging

!layout: Title and Content

**Required diagnostic categories (per storage account):**
- StorageRead — Blob, file, queue, table read operations
- StorageWrite — Write and create operations
- StorageDelete — Delete operations

**Destination:** Log Analytics workspace (same as Sentinel)

**Key tables created:**
| Table | What It Captures |
|---|---|
| StorageBlobLogs | Blob storage read/write/delete operations |
| StorageFileLogs | Azure Files operations |
| StorageQueueLogs | Queue operations |
| StorageTableLogs | Table operations |

**Without these logs enabled, you cannot detect data-plane storage abuse.**

**Speaker Notes:**
Walk students through enabling diagnostic settings in the Azure portal: Storage Account > Diagnostic Settings > Add > select StorageRead, StorageWrite, StorageDelete > send to Log Analytics workspace. This must be done for each storage account individually. In production environments, use Azure Policy to enforce diagnostic settings on all storage accounts. The logs are classified under the Premium tier, so be aware of ingestion costs. The alternative is Basic Logs tier for high-volume storage accounts.

## Slide 6: Key Investigation Fields

!layout: Title and Content

| Field | Purpose | Triage Relevance |
|---|---|---|
| AccountName | Storage account targeted | Scope affected resource |
| OperationName | Action performed (GetBlob, ListBlobs, PutBlob) | Identify attack phase |
| AuthenticationType | OAuth, SAS, AccountKey, Anonymous | Detect unauthorized auth types |
| CallerIpAddress | Source IP of the request | Identify attacker infrastructure |
| RequesterObjectId | Entra object ID for OAuth requests | Who performed the action |
| ObjectKey | Target blob/container path | What was accessed |
| StatusCode | Operation outcome (200, 403, etc.) | Success vs. failed attempts |
| ResponseBodySize | Bytes returned | Calculate data exfiltration volume |
| UserAgentHeader | Client tool fingerprint | Identify tooling used |
| CorrelationId | Cross-resource activity linking | Chain related events |

**Speaker Notes:**
AuthenticationType is the most important field for security analysis. "AccountKey" means the storage account key was used directly — this should be rare in a well-secured environment. "SAS" means a Shared Access Signature was used — check the CallerIpAddress to determine if it's internal or external. "OAuth" means Entra ID authentication, which is the recommended path. "Anonymous" means public access — this should trigger an immediate investigation. ResponseBodySize lets you calculate total data exfiltration volume when aggregated.

## Slide 7: KQL — Detect Storage Key Listing

!layout: Title and Content

```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue ==
    "Microsoft.Storage/storageAccounts/listKeys/action"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress,
          ResourceGroup,
          StorageAccount = tostring(
              split(_ResourceId, "/")[-1])
| order by TimeGenerated desc
```

**What to investigate:**
- Who listed storage keys? Is this a known automation identity?
- From which IP? Is it from expected corporate infrastructure?
- Which storage account? Does it contain sensitive data?

**Speaker Notes:**
This is the control plane detection for the first stage of a storage attack. listKeys is the most dangerous storage operation because it returns the full storage account keys, which provide unlimited data-plane access. In a well-secured environment, listKeys should only come from automation pipelines or break-glass operations. Any interactive user listing keys warrants investigation. Combined with the data-plane queries that follow, this tells you who obtained the keys AND what they did with them.

## Slide 8: KQL — Anomalous Blob Access Patterns

!layout: Title and Content

```kql
StorageBlobLogs
| where TimeGenerated > ago(7d)
| where StatusCode == 200
| where OperationType in (
    "GetBlob", "GetBlobProperties", "ListBlobs")
| summarize
    ReadCount = count(),
    DataTransferMB = sum(ResponseBodySize)
        / 1048576.0,
    DistinctBlobs = dcount(ObjectKey),
    DistinctIPs = dcount(CallerIpAddress),
    IPs = make_set(CallerIpAddress, 10)
    by AccountName, AuthenticationType,
    bin(TimeGenerated, 1h)
| where ReadCount > 100 or DataTransferMB > 500
| order by DataTransferMB desc
```

**What this detects:** High-volume blob reads — an attacker downloading large amounts of data or enumerating many blobs in a short window.

**Speaker Notes:**
This is the data-plane exfiltration detection query. It aggregates successful blob reads by storage account and authentication type in hourly windows. ReadCount > 100 catches enumeration (listing many blobs). DataTransferMB > 500 catches bulk downloads. The AuthenticationType breakdown shows whether the access used keys, SAS, or OAuth. Multiple distinct IPs accessing the same account with keys or SAS is suspicious. Adjust the thresholds based on your environment's normal access patterns.

## Slide 9: KQL — SAS Token Usage from External IPs

!layout: Title and Content

```kql
StorageBlobLogs
| where TimeGenerated > ago(7d)
| where AuthenticationType == "SAS"
| where StatusCode == 200
| extend IsPrivateIP = CallerIpAddress matches regex
    @"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
| where not(IsPrivateIP)
| summarize
    AccessCount = count(),
    DataMB = sum(ResponseBodySize) / 1048576.0,
    Operations = make_set(OperationType),
    Containers = make_set(
        tostring(split(ObjectKey, "/")[1]))
    by AccountName, CallerIpAddress,
    bin(TimeGenerated, 1h)
| order by DataMB desc
```

**What this detects:** SAS-authenticated blob access from external (non-RFC1918) IP addresses — a strong indicator of leaked or stolen SAS tokens.

**Speaker Notes:**
SAS tokens are designed for delegated access, but they're frequently leaked or generated by attackers from stolen keys. This query filters for SAS-authenticated access from non-private IP addresses. In most enterprise environments, internal SAS usage comes from private IPs (VNet, private endpoints). External SAS access warrants investigation — check whether it's a legitimate partner integration or an attacker exfiltrating data. The DataMB aggregation shows how much data was transferred, and the Containers set shows which containers were accessed.

## Slide 10: Defender for Storage Alerts

!layout: Title and Content

| Alert Category | Examples | Severity |
|---|---|---|
| Malware detection | Malicious content uploaded, malware download | High |
| Suspicious SAS activity | External SAS usage, overly permissive tokens | Medium-High |
| Suspicious access | Unusual data exploration, public access changes | Medium |
| Data exfiltration | Unusual volume/count, mass deletion, ACL changes | High |
| Reconnaissance | Container enumeration, access from Tor/unusual locations | Medium |

**Enable Defender for Storage** (per subscription) for automated detection of:
- Malware uploads and downloads with hash-based scanning
- SAS token anomalies and misuse patterns
- Anomalous access volume and geographic patterns

**Speaker Notes:**
Defender for Storage provides automated detection that complements your KQL hunting queries. The malware scanning capability is unique — it scans uploaded and downloaded blobs against known malware signatures. The SAS anomaly detection catches tokens that are overly permissive or used from unexpected locations. Enable Defender for Storage at the subscription level for comprehensive coverage. The alerts feed into Defender for Cloud and can trigger Sentinel analytics rules.

## Slide 11: Incident Response and Hardening

!layout: Title and Content

**Immediate Response:**
- Rotate storage account keys immediately (both key1 and key2)
- Revoke exposed SAS paths (regenerate keys to invalidate all SAS tokens derived from them)
- Restrict network access (enable firewall rules, private endpoints)
- Disable compromised principals and revoke excessive RBAC roles

**Hardening Controls:**
| Control | What It Prevents |
|---|---|
| Entra ID authentication (OAuth) | Eliminates shared key dependency |
| Disable shared key access | Forces all access through Entra ID |
| User delegation SAS | SAS tokens bound to Entra ID, not account keys |
| Storage firewall + private endpoints | Network-level access restriction |
| Key rotation automation | Limits key exposure window |
| Defender for Storage | Automated threat detection |

**Speaker Notes:**
The most impactful hardening control is moving from shared key authentication to Entra ID (OAuth). When you disable shared key access, all data-plane operations must use Entra ID tokens, which are revocable, auditable, and subject to Conditional Access. User delegation SAS replaces account key-based SAS — if the user's access is revoked, the SAS becomes invalid. Storage firewalls and private endpoints restrict network access to approved VNets. Rotation automation limits the window of exposure if keys are compromised.

## Slide 12: Key Takeaways and References

!layout: Title and Content

- Storage has two access planes: control (AzureActivity) and data (StorageBlobLogs) — both must be monitored
- listKeys is the most dangerous control-plane operation — it provides unlimited data-plane access
- SAS tokens from external IPs are a high-priority detection signal
- Defender for Storage provides automated malware scanning and anomaly detection
- Move to Entra ID authentication and disable shared key access as the definitive hardening control

**References:**
| Resource | Link |
|---|---|
| Storage Security Guide | learn.microsoft.com/azure/storage/common/storage-security-guide |
| Defender for Storage | learn.microsoft.com/azure/defender-for-cloud/defender-for-storage-introduction |
| StorageBlobLogs Schema | learn.microsoft.com/azure/azure-monitor/reference/tables/storagebloblogs |
| Disable Shared Key Access | learn.microsoft.com/azure/storage/common/shared-key-authorization-prevent |

**Speaker Notes:**
Module 04 is shorter than the identity modules but the key lesson is profound: without StorageBlobLogs, you're blind to the most impactful part of the attack — the actual data exfiltration. Encourage students to verify diagnostic settings on their production storage accounts immediately after this session. Module 05 shifts to persistence mechanisms — service principal backdoors, federated identity credentials, and managed identity abuse.
