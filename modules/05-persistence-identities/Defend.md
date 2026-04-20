# Defend - Module 05 (Persistence via Identities)

## Defensive Controls

- Prefer managed identities where possible to reduce secret sprawl.
- If service principals are required, prefer certificates over shared secrets.
- Protect keys and certificates in Azure Key Vault.
- Apply least privilege to app roles and RBAC assignments.

## Governance Priorities

1. Restrict who can register apps and manage credentials.
2. Review and approve federated identity issuers and subjects.
3. Monitor sensitive operations on applications and service principals.
4. Enforce periodic access reviews for privileged workload identities.

## Detection Objectives

- Detect credential additions and auth method changes.
- Detect anomalous service principal behavior and suspicious API traffic.
- Detect privilege escalation via app role assignments.

## Microsoft Learn References

- Service principal security guidance: https://learn.microsoft.com/entra/architecture/service-accounts-principal
- Workload identity risk detections: https://learn.microsoft.com/entra/id-protection/concept-workload-identity-risk
- Workload authorization guidance: https://learn.microsoft.com/entra/architecture/authorize-applications-resources-workloads
