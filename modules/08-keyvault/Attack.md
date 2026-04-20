# Attack - Module 08 (Key Vault Abuse)

## Attack Patterns

1. Secret and key enumeration from compromised identities.
2. Access-policy/RBAC manipulation to unlock previously denied secrets.
3. Credentialed access from suspicious IPs, unusual users, or abnormal app-user pairs.

## Typical Adversary Sequence

- Gain foothold in identity plane (user, service principal, or workload identity).
- Probe Key Vault with list/get operations.
- Modify access controls (where possible) and retry secret retrieval.
- Use extracted secrets/certs/keys to pivot to downstream systems.

## High-Signal Indicators

- Spikes in key vault operations by a principal (`KV_OperationVolumeAnomaly`).
- Policy-change followed by secret-get patterns (`KV_PutGetAnomaly`).
- Secret listing followed by query activity (`KV_ListGetAnomaly`).
- Access from suspicious IP or Tor (`KV_SuspiciousIPAccess`, `KV_TORAccess`).

## Microsoft Learn References

- Defender for Key Vault overview: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-key-vault-introduction
- Azure Key Vault alerts reference: https://learn.microsoft.com/azure/defender-for-cloud/alerts-azure-key-vault
- Key Vault logging: https://learn.microsoft.com/azure/key-vault/general/logging
