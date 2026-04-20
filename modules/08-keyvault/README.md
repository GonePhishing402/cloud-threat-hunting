# Module 08 — Key Vault Abuse in Azure

## Objective

Hunt for unauthorized access to Azure Key Vault, including anomalous secret reads, policy manipulation, and identity-driven abuse patterns. Students correlate management-plane and data-plane telemetry to scope impact and respond.

## Duration

~2 to 3 hours (lecture + hands-on labs)

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Unsecured Credentials | T1552 | Credential Access |
| Valid Accounts: Cloud Accounts | T1078.004 | Persistence, Defense Evasion |
| Account Manipulation | T1098 | Persistence |
| Exfiltration Over Web Service | T1567 | Exfiltration |

## Sentinel / Log Tables

- `AZKVAuditLogs` / `AzureDiagnostics` - Key Vault audit operations
- `AZKVPolicyEvaluationDetailsLogs` - Policy evaluation details
- `AzureActivity` - Subscription/resource management operations

## Key Scenarios

1. Suspicious secret enumeration and retrieval.
2. Access-policy or RBAC changes followed by secret access.
3. Access from suspicious IP/Tor/unusual user-app patterns.
