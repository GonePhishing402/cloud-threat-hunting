# Attack - Module 04 (Storage and Key Vault Abuse)

## Attack Patterns

1. Storage account key exposure and shared key abuse.
2. SAS token misuse for broad or long-lived data access.
3. Key Vault secret/key enumeration for cloud pivoting.

## Typical Adversary Sequence

- Obtain account key or over-broad role.
- Generate or steal SAS artifacts.
- Read/exfiltrate blobs or pull sensitive secrets and keys.
- Use stolen secrets to access downstream cloud services.

## High-Signal Indicators

- Key listing operations from unusual callers.
- SAS-authenticated access from unexpected locations.
- Bursty SecretGet or KeyGet operations by unusual principals.

## Microsoft Learn References

- Authorize access to Azure Storage data: https://learn.microsoft.com/azure/storage/common/authorize-data-access
- Shared key authorization prevention: https://learn.microsoft.com/azure/storage/common/shared-key-authorization-prevent
- Secure your Azure Key Vault: https://learn.microsoft.com/azure/key-vault/general/secure-key-vault
