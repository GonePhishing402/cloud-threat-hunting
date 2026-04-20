# Mitigate - Module 03 (Logic App Abuse)

## Incident Mitigation Playbook

1. Disable or isolate suspicious workflows immediately.
2. Revoke/limit managed identity permissions linked to the workflow.
3. Rotate secrets/keys that could have been exposed through workflow output.
4. Block malicious endpoints used by connectors or callbacks.

## Recovery and Hardening

- Rebuild workflows using managed identity and least privilege.
- Restrict inbound IP ranges for request-based triggers.
- Add monitoring for workflow changes and high-frequency triggers.

## Verification

- No unauthorized workflow runs after containment.
- Managed identities show only expected role assignments.
- Alerts fire on new external connector destinations.

## Microsoft Learn References

- Secure access and inbound restrictions: https://learn.microsoft.com/azure/logic-apps/logic-apps-securing-a-logic-app
- Managed identity setup and use: https://learn.microsoft.com/azure/logic-apps/authenticate-with-managed-identity
- Key Vault overview (for secret hygiene): https://learn.microsoft.com/azure/key-vault/general/overview
