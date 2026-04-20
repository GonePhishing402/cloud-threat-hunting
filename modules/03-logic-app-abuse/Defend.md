# Defend - Module 03 (Logic App Abuse)

## Defensive Controls

- Use least-privilege RBAC for workflow creation and editing.
- Prefer managed identity authentication over embedded credentials.
- Restrict inbound trigger exposure and protect callback URLs.
- Apply network restrictions and access controls for workflow endpoints.

## Control Priorities

1. Separate who can build workflows from who can grant identity privileges.
2. Review connector usage and deny risky connector patterns where possible.
3. Enable and monitor diagnostic logs for runtime and management actions.

## Detection Objectives

- Detect suspicious workflow writes/runs.
- Detect external destinations and unusual run cadence.
- Detect managed identity role drift tied to workflow changes.

## Microsoft Learn References

- Secure workflows and connectors: https://learn.microsoft.com/azure/logic-apps/logic-apps-securing-a-logic-app
- Managed identities for Logic Apps: https://learn.microsoft.com/azure/logic-apps/authenticate-with-managed-identity
- Azure RBAC overview: https://learn.microsoft.com/azure/role-based-access-control/overview
