# Mitigate - Module 04 (Storage Abuse)

## Incident Mitigation Playbook

1. Rotate storage account keys and revoke exposed SAS paths.
2. Restrict network access to storage immediately.
3. Revoke excessive roles and disable compromised principals.
4. Rotate exposed secrets and certificates downstream.

## Recovery and Hardening

- Move data-plane access to Entra ID + managed identities.
- Disable Shared Key where platform support allows.
- Enforce SAS expiration policy and monitor out-of-policy use.
- Build detections for anomalous storage reads and SAS misuse patterns.

## Verification

- Shared key usage drops to approved exceptions only.
- No continued suspicious storage access after remediation.
- Data exfil alerts and response playbooks validate in testing.

## Microsoft Learn References

- Protect storage access keys: https://learn.microsoft.com/azure/storage/common/authorize-data-access#protect-your-access-keys
- SAS governance guidance: https://learn.microsoft.com/azure/storage/common/sas-expiration-policy
- Blob monitoring scenarios: https://learn.microsoft.com/azure/storage/blobs/blob-storage-monitoring-scenarios
