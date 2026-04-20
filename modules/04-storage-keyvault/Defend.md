# Defend - Module 04 (Storage and Key Vault Abuse)

## Defensive Controls

- Prefer Microsoft Entra authorization with managed identities.
- Disallow Shared Key authorization whenever possible.
- Use user delegation SAS with narrow scope and short expiry.
- Apply private networking and strict firewall/network ACL controls.

## Key Vault Defensive Baseline

1. Enable RBAC-based access governance.
2. Enable logging and alerting for management/data plane actions.
3. Enforce soft delete and purge protection.
4. Use key/secret rotation and expiry policies.

## Detection Objectives

- Detect `listKeys` and high-risk key operations.
- Detect unusual SAS usage and high-volume reads.
- Detect secret enumeration and abuse patterns.

## Microsoft Learn References

- Storage authorization guidance: https://learn.microsoft.com/azure/storage/common/authorize-data-access
- Blob security best practices: https://learn.microsoft.com/azure/well-architected/service-guides/azure-blob-storage
- Key Vault security baseline: https://learn.microsoft.com/security/benchmark/azure/baselines/key-vault-security-baseline
