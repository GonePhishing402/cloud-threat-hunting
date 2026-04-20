# Mitigate - Module 05 (Persistence via Identities)

## Incident Mitigation Playbook

1. Remove unauthorized secrets, certificates, and federated credentials.
2. Disable compromised service principals and rotate surviving credentials.
3. Revoke excessive app roles and RBAC assignments.
4. Investigate and contain downstream resource actions performed by the identity.

## Recovery and Hardening

- Migrate credentialed workloads to managed identities where feasible.
- Enforce certificate-first policy for remaining service principals.
- Limit app registration rights and add strict review controls.
- Deploy alerts for sensitive identity operations and anomalous SP sign-ins.

## Verification

- No unapproved federated credentials remain.
- No long-lived legacy secrets outside policy.
- Post-remediation sign-ins align with expected workload behavior.

## Microsoft Learn References

- Service principal hardening: https://learn.microsoft.com/entra/architecture/service-accounts-principal
- Federated identity credential restrictions: https://learn.microsoft.com/entra/workload-id/workload-identity-federation-considerations
- Workload identity governance and risk: https://learn.microsoft.com/entra/id-protection/concept-workload-identity-risk
