# Mitigate - Module 08 (Key Vault Abuse)

## Incident Mitigation Playbook

1. Disable or contain compromised principals accessing Key Vault.
2. Revoke unauthorized RBAC/access-policy changes.
3. Rotate exposed secrets, keys, and certificates immediately.
4. Restrict vault network access (private endpoint/firewall) while investigation continues.

## Recovery and Hardening

- Enforce least privilege and separation of duties for vault administration.
- Require logging and alerting for all key vaults via policy.
- Validate Defender for Key Vault plan coverage across subscriptions.
- Add analytics and SOAR workflows for suspicious key-vault operation sequences.

## Verification

- No continued anomalous secret/key operations after containment.
- No unauthorized policy or RBAC drift.
- Alerts are routed and actionable in SOC workflow tooling.

## Microsoft Learn References

- Secure your Azure Key Vault: https://learn.microsoft.com/azure/key-vault/general/secure-key-vault
- Configure Key Vault networking: https://learn.microsoft.com/azure/key-vault/general/network-security
- Respond to Defender for Key Vault alerts: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-key-vault-introduction#respond-to-microsoft-defender-for-key-vault-alerts
- Manage/respond to Defender for Cloud alerts: https://learn.microsoft.com/azure/defender-for-cloud/manage-respond-alerts
