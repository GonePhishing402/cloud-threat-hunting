# Attack Techniques: Azure Key Vault

## Common Attack Patterns
- Credential theft and secret enumeration (compromised identities listing and retrieving secrets)
- Policy or RBAC manipulation to unlock previously denied secrets
- Access from suspicious IPs, TOR exit nodes, or unusual user-app pairs
- Secret dumping: Secret List followed by Secret Get operations
- High volume of anomalous operations by a single principal

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Unsecured Credentials | T1552 | Credential Access |
| Valid Accounts: Cloud Accounts | T1078.004 | Persistence, Defense Evasion |
| Account Manipulation | T1098 | Persistence |
| Exfiltration Over Web Service | T1567 | Exfiltration |

## High-Signal Defender for Key Vault Alerts

| Alert ID | Description | Severity |
|---|---|---|
| KV_SuspiciousIPAccess | Access from a suspicious IP identified by Microsoft Threat Intelligence | Medium |
| KV_TORAccess | Access from a known TOR exit node | Medium |
| KV_OperationVolumeAnomaly | Anomalous number of operations by a user/service principal | Medium |
| KV_PutGetAnomaly | Policy change followed by Secret Get operations | Medium |
| KV_ListGetAnomaly | Secret List followed by Secret Get (secret dumping pattern) | Medium |
| KV_UserAnomaly | Vault accessed by a user that does not normally access it | Medium |
| KV_UserAppAnomaly | Vault accessed by an unusual user-app pair | Medium |
| KV_AppAnomaly | Vault accessed by a service principal that does not normally access it | Medium |
| KV_SuspiciousIPAccessDenied | Failed access attempt from a suspicious IP | Low |

## Microsoft Learn References
- [Alerts for Azure Key Vault](https://learn.microsoft.com/azure/defender-for-cloud/alerts-azure-key-vault)
- [Defender for Key Vault introduction](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-key-vault-introduction)
- [Key Vault logging](https://learn.microsoft.com/azure/key-vault/general/logging)