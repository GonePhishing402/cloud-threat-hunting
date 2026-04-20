# Defend: Azure Key Vault

## Identity & Access Management
- Use **Azure RBAC** (not legacy access policies) for all data plane operations — [RBAC guide](https://learn.microsoft.com/azure/key-vault/general/rbac-guide)
- Use **managed identities** for all app and service connections to eliminate hard-coded credentials
- Apply **least privilege**; use Privileged Identity Management (PIM) for JIT admin role activation
- Require **MFA** and approvals for privileged role activation
- Enable **Conditional Access** policies for Key Vault access

## Network Security
- Disable public network access and use **Private Endpoints** — [Private Link](https://learn.microsoft.com/azure/key-vault/general/private-link-service)
- Enable the **Key Vault firewall** and restrict to known IP ranges / virtual networks
- Consider Network Security Perimeter for PaaS isolation — [Network security](https://learn.microsoft.com/azure/key-vault/general/network-security)

## Data Protection
- Enable **soft delete** (7–90 day retention) and **purge protection** — [Soft delete overview](https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview)
- Configure **autorotation** for keys, secrets, and certificates — [Key autorotation](https://learn.microsoft.com/azure/key-vault/keys/how-to-configure-key-rotation)
- Use one Key Vault per application, region, and environment to minimize blast radius

## Logging & Threat Detection
- Enable **audit logging** via Diagnostic Settings (category: `AuditEvent` / `allLogs`) — [Key Vault logging](https://learn.microsoft.com/azure/key-vault/general/logging)
- Enable **Microsoft Defender for Key Vault** — [Defender for Key Vault](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-key-vault-introduction)
- Set up **log alerts** for critical events (access failures, secret deletions) — [Monitoring and alerting](https://learn.microsoft.com/azure/key-vault/general/alert)
- Integrate with **Event Grid** for near-real-time notifications on key/secret/cert changes

## Log Analytics Tables

| Table | Purpose |
|---|---|
| `AZKVAuditLogs` | Key Vault data-plane audit operations (recommended) |
| `AzureDiagnostics` | Multi-resource table; filter by `ResourceProvider == "MICROSOFT.KEYVAULT"` |
| `AzureActivity` | Management-plane operations (RBAC changes, vault creation/deletion) |

## Compliance & Governance
- Use **Azure Policy** to enforce diagnostic settings and secure configuration at scale — [Policy built-ins](https://learn.microsoft.com/azure/key-vault/policy-reference)
- Audit key expiration dates and rotation compliance via built-in policy definitions

## Microsoft Learn References
- [Secure your Azure Key Vault](https://learn.microsoft.com/azure/key-vault/general/secure-key-vault)
- [Azure Key Vault security baseline](https://learn.microsoft.com/security/benchmark/azure/baselines/key-vault-security-baseline)
- [Best practices for protecting secrets](https://learn.microsoft.com/azure/security/fundamentals/secrets-best-practices)