# Attack - Module 05 (Persistence via Identities)

## Attack Patterns

1. Add credentials to existing service principals for stealth persistence.
2. Add federated identity credentials that trust attacker-controlled issuers.
3. Abuse managed identity assignments to preserve privileged cloud access.

## Typical Adversary Sequence

- Compromise identity with app/admin permissions.
- Add secret/certificate or federated trust relationship.
- Reauthenticate as workload identity outside normal user controls.
- Use granted permissions for long-lived access and further privilege actions.

## High-Signal Indicators

- Unexpected service principal credential additions.
- New federated identity credentials with unfamiliar issuer/subject values.
- Service principal sign-ins from unusual locations or workloads.

## Microsoft Learn References

- Securing service principals: https://learn.microsoft.com/entra/architecture/service-accounts-principal
- Workload identity federation overview: https://learn.microsoft.com/entra/workload-id/workload-identity-federation
- Federated credential considerations: https://learn.microsoft.com/entra/workload-id/workload-identity-federation-considerations
