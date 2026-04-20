# Attack - Module 04 (Storage Abuse)

## Attack Patterns

1. Storage account key exposure and shared key abuse.
2. SAS token misuse for broad or long-lived data access.
3. Blob and container reconnaissance to stage large-volume exfiltration.

## Typical Adversary Sequence

- Obtain account key or over-broad role.
- Generate or steal SAS artifacts.
- Enumerate and read sensitive blobs with shared key or SAS auth.
- Exfiltrate data from attacker-controlled infrastructure.

## High-Signal Indicators

- Key listing operations from unusual callers.
- SAS-authenticated access from unexpected locations.
- Bursty read/list operations from unusual principals or source IPs.

## Microsoft Learn References

- Authorize access to Azure Storage data: https://learn.microsoft.com/azure/storage/common/authorize-data-access
- Shared key authorization prevention: https://learn.microsoft.com/azure/storage/common/shared-key-authorization-prevent
- Azure Blob monitoring scenarios: https://learn.microsoft.com/azure/storage/blobs/blob-storage-monitoring-scenarios
