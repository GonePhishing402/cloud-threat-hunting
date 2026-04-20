# Mitigate - Module 04 (Storage and Key Vault Abuse)

## Incident Mitigation Playbook

1. Rotate storage account keys and revoke exposed SAS paths.
2. Restrict network access to storage and Key Vault immediately.
3. Revoke excessive roles and disable compromised principals.
4. Rotate exposed secrets and certificates downstream.

## Recovery and Hardening

- Move data-plane access to Entra ID + managed identities.
- Disable Shared Key where platform support allows.
- Enforce SAS expiration policy and monitor out-of-policy use.
- Build detections for anomalous storage reads and Key Vault enumeration.

## Verification

- Shared key usage drops to approved exceptions only.
- No continued suspicious secret access after remediation.
- Data exfil alerts and response playbooks validate in testing.

## Microsoft Learn References

- Protect storage access keys: https://learn.microsoft.com/azure/storage/common/authorize-data-access#protect-your-access-keys
- SAS governance guidance: https://learn.microsoft.com/azure/storage/common/sas-expiration-policy
- Key Vault monitoring and logging: https://learn.microsoft.com/azure/key-vault/general/logging
