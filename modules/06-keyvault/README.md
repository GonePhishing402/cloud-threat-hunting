# Module 06 — Azure Key Vault Abuse

## Objective
Hunt for unauthorized access to Azure Key Vault, including anomalous secret reads, policy manipulation, and identity-driven credential theft. Students correlate management-plane and data-plane telemetry to scope impact and respond effectively.

## Duration
~2 to 3 hours (lecture + hands-on labs)

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Unsecured Credentials | T1552 | Credential Access |
| Valid Accounts: Cloud Accounts | T1078.004 | Persistence, Defense Evasion |
| Account Manipulation | T1098 | Persistence |
| Exfiltration Over Web Service | T1567 | Exfiltration |

## Sentinel / Log Analytics Tables

| Table | Description |
|---|---|
| `AZKVAuditLogs` | Key Vault data-plane audit operations (recommended) |
| `AzureDiagnostics` | Multi-resource; filter by `MICROSOFT.KEYVAULT` |
| `AzureActivity` | Management-plane: RBAC changes, vault-level operations |

## Key Scenarios
1. Suspicious secret enumeration and retrieval by a compromised identity
2. Access-policy or RBAC change followed by secret access
3. Access from suspicious IP, TOR, or unusual user-app pairs
4. High-volume operations indicating automated credential harvesting

## Module Files
- [Attack.md](Attack.md) — Attack techniques and Defender for Key Vault alert mappings
- [Defend.md](Defend.md) — Defensive controls, logging setup, and detection tables
- [Mitigate.md](Mitigate.md) — Incident response playbook and recovery steps

## Microsoft Learn References
- [Secure your Azure Key Vault](https://learn.microsoft.com/azure/key-vault/general/secure-key-vault)
- [Defender for Key Vault introduction](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-key-vault-introduction)
- [Alerts for Azure Key Vault](https://learn.microsoft.com/azure/defender-for-cloud/alerts-azure-key-vault)
- [Key Vault logging](https://learn.microsoft.com/azure/key-vault/general/logging)