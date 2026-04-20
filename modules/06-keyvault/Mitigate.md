# Mitigate: Azure Key Vault Incidents

## Step 1 — Identify the Source
- Verify whether the alert originates from within your Azure tenant
- If the Key Vault firewall is enabled, determine which user or app triggered the alert
- Contact the user or application owner to confirm whether the activity was legitimate
> **Caution:** Do not dismiss an alert simply because you recognize the user or app. Stolen credentials are the most common attack vector. Always verify.

## Step 2 — Respond Accordingly
If the source is unrecognized or access was not authorized:
1. Enable the **Key Vault firewall** and restrict to trusted resources — [Configure network security](https://learn.microsoft.com/azure/key-vault/general/network-security)
2. Remove or restrict the **unauthorized principal** (user, service principal, or app) from RBAC/access policies
3. If the alert involves a Microsoft Entra role, contact your administrator to reduce or revoke permissions

## Step 3 — Measure the Impact
1. Open the **Security** page on the Key Vault and review triggered alerts
2. Identify the secrets, keys, and certificates accessed, along with timestamps
3. Cross-reference Key Vault diagnostic logs by caller IP, UPN, or object ID

## Step 4 — Take Action
1. **Rotate** all affected secrets, keys, and certificates immediately
2. Disable or delete compromised secrets from the vault
3. Notify application owners to audit for any use of compromised credentials
4. Remediate any downstream systems that may have been accessed with stolen secrets

## Recovery & Hardening
- Enforce least privilege and separation of duties for vault administration
- Require audit logging and Defender for Key Vault across all vaults via Azure Policy
- Test backup and recovery procedures — [Backup guide](https://learn.microsoft.com/azure/key-vault/general/backup)
- Validate Defender for Key Vault plan coverage across subscriptions

## Microsoft Learn References
- [Respond to Defender for Key Vault alerts](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-key-vault-introduction#respond-to-microsoft-defender-for-key-vault-alerts)
- [Manage and respond to alerts](https://learn.microsoft.com/azure/defender-for-cloud/manage-respond-alerts)
- [Azure incident response overview](https://learn.microsoft.com/azure/security/fundamentals/incident-response-overview)